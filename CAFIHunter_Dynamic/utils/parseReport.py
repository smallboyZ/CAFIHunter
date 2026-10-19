# -*- coding:utf-8 -*-

import json
import re
import os
from utils.config import *
from utils.adbTools import log

def getJsonData(inPath):
    with open(inPath,"r",encoding='utf-8') as f:
        return json.load(f)
def saveJsonData(record,path):
    if(not os.path.exists(path)):
        with open(path, 'w', encoding='utf-8') as f:
            f.write("{}")
    with open(path,'r',encoding='utf-8') as f:
        data=json.load(f)
    for k,v in record.items():
        data[k]=v
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data,f,indent=2,ensure_ascii=False)
def split_blocks(text: str) -> list[str]:
    blocks = re.split(r'(?m)^\={5,}\s*$', text)
    return [b.strip() for b in blocks if b.strip()]

def parse_items_from_bracket_content(content: str) -> list[str]:
    if content is None:
        return []
    content = content.strip()
    if content == '':
        return []
    quoted = re.findall(r'"([^"]+)"', content)
    if quoted:
        return [q.strip() for q in quoted if q.strip()]
    angle = re.findall(r'<([^>]+)>', content)
    if angle:
        return [f"<{a.strip()}>" for a in angle if a.strip()]
    parts = [p.strip() for p in content.split(',')]
    return [p for p in parts if p]

def extract_field_bracket(block: str, field_name: str) -> list[str]:
    m = re.search(r'(?mi)^\s*' + re.escape(field_name) + r'\s*:\s*\[([^\]]*)\]', block)
    if not m:
        return []
    return parse_items_from_bracket_content(m.group(1))

def extract_field_line(block: str, field_name: str) -> str:
    m = re.search(r'(?m)^\s*' + re.escape(field_name) + r'\s*:\s*(.+)$', block)
    if not m:
        return ""
    return m.group(1).strip()

def parse_fa_component_block(block: str, fa_dict: dict):
    if 'FAComponent:' not in block:
        return
    m = re.search(r'FAComponent:\s*(\S+)', block)
    if not m:
        return
    name = m.group(1).strip()
    actions = extract_field_bracket(block, 'actions')
    dataSchemes = extract_field_bracket(block, 'dataSchemes')
    dataSchemes = [s for s in dataSchemes if s]
    mimeTypes = extract_field_bracket(block, 'mimeTypes')
    pathPatterns = extract_field_bracket(block, 'pathPatterns')
    fa_dict[name] = {
        "actions": actions,
        "dataSchemes": dataSchemes,
        "mimeTypes": mimeTypes,
        "pathPatterns": pathPatterns
    }

def parse_loader_site_block(block: str) -> dict:
    if '[Loader Site]:' not in block:
        return None

    sink = {
        "Loader Site": "",
        "Load Method": "",
        "getColumnValue": [],
        "getExtras": [],
        "checkValue": [],
        "fileHandler": [],
        "uriHandler": [],
        "sink_query": [],
        "sink_open": []
    }

    ls = extract_field_line(block, '[Loader Site]')
    sink["Loader Site"] = ls

    lm = extract_field_line(block, '[Load Method]')
    if lm:
        sink["Load Method"] = lm

    m_cols = re.search(r'(?m)getColumnValue#\s*\[([^\]]*)\]', block)
    if m_cols:
        cols = re.findall(r'"([^"]+)"', m_cols.group(1))
        sink["getColumnValue"] = [c.strip() for c in cols if c.strip()]

    m_extras = re.search(r'(?m)getExtras#\s*\[([^\]]*)\]', block)
    if m_extras:
        sink["getExtras"] = parse_items_from_bracket_content(m_extras.group(1))

    m_check = re.search(r'(?m)checkValue#\s*\[([^\]]*)\]', block)
    if m_check:
        raw = m_check.group(1).strip()
        if raw:
            parts = [p.strip() for p in raw.split(',') if p.strip()]
            cleaned = []
            for p in parts:
                p = re.sub(r'(?i)^Check#', '', p).strip()
                p = p.replace('"', '')
                cleaned.append(p)
            sink["checkValue"] = cleaned

    m_fh = re.search(r'(?m)fileHandler#\s*\[([^\]]*)\]', block)
    if m_fh:
        items = re.findall(r'<([^>]+)>', m_fh.group(1))
        sink["fileHandler"] = [f"<{it.strip()}>" for it in items if it.strip()]

    m_uh = re.search(r'(?m)uriHandler#\s*\[([^\]]*)\]', block)
    if m_uh:
        items = re.findall(r'<([^>]+)>', m_uh.group(1))
        sink["uriHandler"] = [f"<{it.strip()}>" for it in items if it.strip()]

    last_sink_type = None
    for raw_line in block.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith('SINK METHOD:'):
            method_text = line.split(':', 1)[1].strip().lower()
            if 'query(' in method_text or ' query<' in method_text or ': android.database.cursor query' in method_text:
                last_sink_type = 'sink_query'
            elif any(k in method_text for k in ('openinputstream', 'openfiledescriptor', 'openassetfiledescriptor')):
                last_sink_type = 'sink_open'
            else:
                last_sink_type = None
        elif line.startswith('LOCATION:'):
            loc = line.split(':', 1)[1].strip()
            if last_sink_type:
                sink[last_sink_type].append(loc)

    return sink

def parse_txt_to_json(file_path: str) -> dict:
    with open(file_path, 'r', encoding='utf-8') as f:
        text = f.read()

    blocks = split_blocks(text)

    fa_component = {}
    sink_methods = []

    for block in blocks:
        if 'FAComponent:' in block:
            parse_fa_component_block(block, fa_component)

        if '[Loader Site]:' in block:
            sink_obj = parse_loader_site_block(block)
            if sink_obj:
                sink_methods.append(sink_obj)

    result = {
        "FAComponent": fa_component,
        "sinkMethod": sink_methods
    }
    return result

def generate_dynamic_input(pkgs):
    for pkg in pkgs:
        outPath=os.path.join(dynamic_input,pkg+".json")
        if os.path.exists(outPath):
            log(f"The dynamic input of {pkg} has been generated")
            continue
        inPath=os.path.join(static_records,pkg+".txt")
        if os.path.exists(inPath):
            log(f"Generate the dynamic input of {pkg}")
            try:
                res=parse_txt_to_json(inPath)
                with open(outPath, 'w', encoding='utf-8') as f:
                    json.dump(res, f, indent=4, ensure_ascii=False)
            except:
                log(f"An error occurred while generating the dynamic input for {pkg} ;-( ")
        else:
            log(f"No static analysis results were found for {pkg} ;-( ")

def generate_dynamic_input_dir(strDir=static_records):
    sr=os.listdir(strDir)
    for f in sr:
        if not f.endswith(".txt"):
            continue
        pkg=f[:-4]
        inPath = os.path.join(strDir, f)
        outPath = os.path.join(dynamic_input, pkg+'.json')
        if os.path.exists(inPath):
            log(f"Generate the dynamic input of {f[:-4]}")
            try:
                res=parse_txt_to_json(inPath)
                with open(outPath, 'w', encoding='utf-8') as f:
                    json.dump(res, f, indent=4, ensure_ascii=False)
            except:
                log(f"An error occurred while generating the dynamic input for {pkg} ;-( ")
        else:
            log(f"No static analysis results were found for {pkg} ;-( ")

