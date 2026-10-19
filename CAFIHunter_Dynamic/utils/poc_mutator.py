# -*- coding:utf-8 -*-
import datetime
import json
import random
import time
from dataclasses import dataclass
from typing import List, Dict, Optional
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

@dataclass
class Constraint:
    op: str
    value: str

@dataclass
class SinkProfile:
    load_method: str
    columns: List[str]
    extras: List[str]
    constraints: List[Constraint]
    uri_handlers: List[str]

def parse_constraints(check_values: List[str]) -> List[Constraint]:
    out = []
    for raw in check_values or []:
        if ":" not in raw:
            continue
        op, val = raw.split(":", 1)
        out.append(Constraint(op=op.strip(), value=val.strip()))
    return out

def parse_sink_profiles(doc: Dict) -> List[SinkProfile]:
    profiles = []
    for sm in doc.get("sinkMethod", []) or []:
        profiles.append(SinkProfile(
            load_method=sm.get("Load Method", "") or "UNKNOWN",
            columns=sm.get("getColumnValue", []) or [],
            extras=sm.get("getExtras", []) or [],
            constraints=parse_constraints(sm.get("checkValue", []) or []),
            uri_handlers=sm.get("uriHandler", []) or []
        ))
    return profiles

def base_uri_parts(base_uri: str):
    sp = urlsplit(base_uri)
    q = dict(parse_qsl(sp.query, keep_blank_values=True))
    return sp, q

def build_uri(base_uri: str, path: str, query_params: Dict[str, str]) -> str:
    sp, q = base_uri_parts(base_uri)
    q.update(query_params)
    return urlunsplit((sp.scheme, sp.netloc, path, urlencode(q, doseq=True), sp.fragment))

def unique(seq: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in seq:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out

def extract_path_prefixes(cons: List[Constraint]) -> List[str]:
    prefixes=[]
    for c in cons:
        if c.op=="startsWith" and c.value:
            v=c.value
            if '/' in v and ':' not in v:
                for bt in BASE_MIME_TYPES:
                    if v.startswith(bt):
                        break
                else:
                    prefixes.append(c.value)
    return prefixes
def extract_startsWith(cons: List[Constraint]) -> List[str]:
    return [c.value for c in cons if c.op == "startsWith" and c.value]

def extract_contains(cons: List[Constraint]) -> List[str]:
    return [c.value for c in cons if c.op == "contains" and c.value]

def extract_equals(cons: List[Constraint]) -> List[str]:
    return [c.value for c in cons if c.op in ("equalsIgnoreCase", "equals") and c.value]

def extract_extension_like(cons: List[Constraint]) -> List[str]:
    exts = []
    for c in cons:
        if c.op in ("endsWith", "equalsIgnoreCase", "equals"):
            v = (c.value or "").strip().replace(" ","")
            if not v:
                continue
            if v.startswith(".") and (len(v) <= 8):
                exts.append(v if v.startswith(".") else "." + v)
    return unique(exts)

BASE_MIME_TYPES=["text","image","application","audio","video"]
def looks_like_mime(s: str) -> bool:
    s = (s or "").strip()
    if "/" not in s:
        return False
    left, right = s.split("/", 1)
    if not left or not right:
        return False
    if left not in BASE_MIME_TYPES:
        return False
    return True

def extract_mime_like(cons: List[Constraint]) -> List[str]:
    mimes = []
    for c in cons:
        v = (c.value or "").strip()
        if looks_like_mime(v):
            mimes.append(v)
    return unique(mimes)


def likely_authority_checks(profile: SinkProfile) -> bool:
    return any(
        ("android.net.Uri" in h and ("getAuthority" in h or "getHost" in h))
        for h in profile.uri_handlers
    )

def filter_authority(auth_str):
    black_lists=["/","java.lang","android.intent"]
    if "." not in auth_str or len(auth_str)<2:
        return False
    for bl in black_lists:
        if bl in auth_str:
            return False
    return True

def join_prefix(prefix: str, payload: str) -> str:
    prefix = prefix.rstrip("/")
    rel = payload.lstrip("/")
    if not prefix:
        return rel
    return f"{prefix}/{rel}"

def mutate_path(base_payloads: List[str], prefixes: List[str],exts:List[str]) -> List[str]:
    out = []

    out.extend(base_payloads)

    for pref in prefixes or []:
        if "/data/data" in pref or "/data/user" in pref:
            continue

        for p in base_payloads:
            out.append(join_prefix(pref,p))
    return unique(out)

def ensure_suffix(name: str, ext: str) -> str:
    if name.lower().endswith(ext.lower()):
        return name
    return name + ext

def apply_extensions_to_candidates(cands: List[str], exts: List[str]) -> List[str]:
    if not exts:
        return cands
    out = []
    for s in cands:
        out.append(s)
        for ext in exts:
            out.append(ensure_suffix(s, ext))
    return unique(out)

def mutate_authorities(base_authority: str, tokens: List[str], cap: int = 6) -> List[str]:
    cands = [base_authority]
    for t in tokens:
        if not t:
            continue
        cands.append(f"{t}.evil")
        cands.append(f"evil.{t}")
        cands.append(t)
    return unique(cands)[:cap]

def satisfy_path_constraints(profile: SinkProfile) -> List[str]:
    cons = profile.constraints
    prefixes = extract_path_prefixes(cons)
    exts=extract_extension_like(cons)
    candidates = mutate_path(["PLACEHOLDER"], prefixes,exts)
    return candidates

def satisfy_metadata(columns,path_value="PLACEHOLDER") -> Dict[str,str]:
    m = {}
    for col in columns:
        if col in ("_display_name","_data","title","bucket_display_name"):
            m[col] = path_value
        elif col in ("_size","width","height","orientation"):
            m[col] = "1024"
        elif col in ("mime_type"):
            m[col] = "*/*"
        elif col in ("datetaken","date_added","date_modified","date_expires"):
            m[col] = "0"
        else:
            m[col] = "CAFI"
    return m

def get_component_mime_types(doc: Dict) -> List[str]:
    out = []
    fa = doc.get("FAComponent", {}) or {}
    for _, meta in fa.items():
        out.extend(meta.get("mimeTypes", []) or [])
    return unique(out)

def derive_candidate_mime_types(doc: Dict, profile: SinkProfile) -> List[str]:
    observed = extract_mime_like(profile.constraints)
    return unique(observed)

def build_constraint_aware_template(doc: Dict):

    profiles = parse_sink_profiles(doc)
    check_mimeTypes=[]
    authorities=[]
    check_auth=False

    for prof in profiles:
        check_mimeTypes.extend(derive_candidate_mime_types(doc, prof))

    check_mimeTypes=unique(check_mimeTypes)

    path_template=["PLACEHOLDER"]
    default_meta=["_display_name","_size"]
    embed_metadatas=[default_meta]

    for prof in profiles:
        cons = prof.constraints
        auth_tokens=[]
        if likely_authority_checks(prof):
            check_auth=True
            tokens = ["contains#:"+t for t in extract_contains(cons)]
            tokens.extend(["equals#:"+t for t in extract_equals(cons)])
            tokens.extend(["startsWith#:"+t for t in extract_startsWith(cons)])
            for t in tokens:
                tt=t.replace(' ','').split('#:')[1]
                if not filter_authority(tt):
                    continue

                auth_tokens.append(t)

            authorities.extend(auth_tokens)

        path_candidates = satisfy_path_constraints(prof)

        path_template.extend(path_candidates)
        columns=prof.columns
        if columns and columns not in embed_metadatas:
            if len(columns)<=5:
                embed_metadatas.append(columns)

    path_template=unique(path_template)

    result={
            "path_templates":path_template,
            "embed_metadatas":embed_metadatas,
            "authorities": (check_auth,unique(authorities)),
            "check_mimeTypes": check_mimeTypes
    }

    return result
