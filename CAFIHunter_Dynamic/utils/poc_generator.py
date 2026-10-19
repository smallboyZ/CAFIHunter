# -*- coding:utf-8 -*-
import os
from utils.config import dynamic_input
from utils.poc_mutator import *

vuln_actions=["android.intent.action.SEND","android.intent.action.VIEW"]
def select_action(action):
    if action in vuln_actions:
        return True
    if action.endswith(".VIEW"):
        return True
    return False

def filter_mime_types(lst):
    res=[]
    for tp in lst:
        if tp.startswith("*/"):
            continue
        res.append(tp)
    return res
def pick_type_unique(lst,n):
    if not lst:
        return []
    newlst=filter_mime_types(lst)
    if len(newlst)>=1:
        lst=newlst
    if len(lst) < n:
        return lst[:]

    return random.sample(lst, n)

def get_dynamic_input(pkg) ->dict:
    record={}
    try:
        filepath=os.path.join(dynamic_input,pkg+".json")
        if os.path.exists(filepath):
            with open(filepath,'r',encoding='utf-8') as f:
                record=json.load(f)
    except:
        pass
    return record

def merge_list_of_lists(a, b):
    return [list(t) for t in set(tuple(x) for x in (a + b))]

def merge_record(record,feedback):
    record["query_keys"] = merge_list_of_lists(
        record.get("query_keys", []), feedback.get("query_keys", [])
    )
    record["open_pocs"] = list(
        set(record.get("open_pocs", [])) | set(feedback.get("open_pocs", []))
    )
    record["file_paths"] = list(
        set(record.get("file_paths", [])) | set(feedback.get("file_paths", []))
    )

    record["call_getType"] = (
        record.get("call_getType", False) or feedback.get("call_getType", False)
    )
    return record

def extract_poc_template_from_feedback(pkg,feedback_open_pocs:List,payloads:List):
    res=[]
    for open_poc in feedback_open_pocs:
        for payload in sorted(payloads, key=len, reverse=True):
            p=payload.format(pkg=pkg)
            if p in open_poc:
                open_poc=open_poc.replace(p,"PLACEHOLDER")
                break
        res.append(open_poc)
    _res=[]
    for p in res:
        if "type=*/*" in p:
            _res.append(p)
    if len(_res)>0:
        return unique(_res)
    return unique(res)

def generate_pocs_from_dynamic_templates(pkg,dynamic_input,dynamic_poc_templates,payloads:List):
    pocs = []
    mutated_payloads=[]
    record =dynamic_input
    poc_mimeTypes=[ poc.split("type=")[-1] for poc in dynamic_poc_templates if "type" in poc]

    FAComponent = {}
    if "FAComponent" in record and record["FAComponent"]:
        FAComponent = record["FAComponent"]


    if len(FAComponent.keys()) == 0:
        return pocs

    if not record:
        return pocs

    for embed_poc in dynamic_poc_templates:
        for payload in payloads:
            payload = payload.format(pkg=pkg)
            if embed_poc.endswith("PLACEHOLDER") and "/" in payload:
                continue
            mutated_payloads.append(embed_poc.replace("PLACEHOLDER", payload))

    for component, info in FAComponent.items():
        actions = info['actions']
        mimeTypes = info['mimeTypes']
        for action in actions:
            if select_action(action):
                for mpayload in mutated_payloads:
                    if "type" in mpayload:
                        mimeType=mpayload.split("type=")[-1]
                        pocs.append((pkg, component, mpayload, mimeType, action))
                    else:
                        if len(poc_mimeTypes)==0:
                            poc_mimeTypes=pick_type_unique(mimeTypes,3)
                        for mimeType in poc_mimeTypes:
                            pocs.append((pkg, component, mpayload, mimeType, action))

    return pocs

def generate_pocs(pkg,dynamic_input,pocTemplates,payloads,scheme="content",base_authority="com.poc.agent.Provider"):

    pocs=[]
    embed_pocs = []

    record=dynamic_input

    if not record:
        return pocs

    FAComponent={}
    if "FAComponent" in record and record["FAComponent"]:
        FAComponent=record["FAComponent"]

    if len(FAComponent.keys())==0:
        return pocs

    base_uri = f"{scheme}://{base_authority}/"

    path_templates=pocTemplates['path_templates']
    embed_metadatas=pocTemplates['embed_metadatas']
    check_mimeTypes=pocTemplates['check_mimeTypes']


    embed_maps = [satisfy_metadata(embed_point) for embed_point in embed_metadatas]

    for pathtm in path_templates:
        for embed_map in embed_maps:
            if(len(embed_map)<=5):
                embed_pocs.append(build_uri(base_uri, "", embed_map).replace("PLACEHOLDER",pathtm))
    uri_paht_embed=[build_uri(base_uri, path, {}) for path in path_templates]
    for i in range(len(uri_paht_embed)):
        embed_pocs.insert(i+len(path_templates),uri_paht_embed[i])
    print(embed_pocs)
    mutated_payloads=[]

    for embed_poc in embed_pocs:
        for payload in payloads:
            payload=payload.format(pkg=pkg)
            if embed_poc.endswith("PLACEHOLDER") and "/" in payload:
                continue
            mutated_payloads.append(embed_poc.replace("PLACEHOLDER",payload))


    for component, info in FAComponent.items():
        actions = info['actions']
        mimeTypes = info['mimeTypes']
        mimeTypes.extend(check_mimeTypes)

        for action in actions:
            if select_action(action):
                for mpayload in mutated_payloads:
                    if '?' not in mpayload:
                        pocs.append((pkg, component, mpayload, "*/*", action))
                    else:
                        if "mime_type" not in mpayload:
                            pocs.append((pkg, component, mpayload + f"&mime_type=*/*", "*/*", action))

                    select_mimeTypes=pick_type_unique(mimeTypes, 3)

                    for mimetype in select_mimeTypes:
                        if mimetype != "*/*":
                            if '?' not in mpayload:
                                pocs.append((pkg, component, mpayload, mimetype, action))
                            else:
                                if "mime_type" not in mpayload:
                                    pocs.append((pkg, component, mpayload + f"&mime_type={mimetype}", mimetype, action))

    return pocs


