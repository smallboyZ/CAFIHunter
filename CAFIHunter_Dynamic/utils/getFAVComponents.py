# -*- coding:utf-8 -*-、
import os
import json
import config as config
from androguard.core.apk import APK
from androguard.core.axml import logger
from concurrent.futures import ThreadPoolExecutor, as_completed
from xml.etree.ElementTree import tostring

logger.disable("androguard.core.axml")
logger.disable("androguard.core.api_specific_resources")


class FAComponent:
    def __init__(self, name):
        self.name = name
        self.actions = []
        self.dataSchemes = []
        self.mimeTypes = []
        self.pathPatterns = []

    def matchesFilter(self):
        for action in self.actions:
            if "SEND" in action.upper():
                return True
        if "file" in self.dataSchemes or "content" in self.dataSchemes:
            return True
        if len(self.mimeTypes):
            return True
        return False

def is_reachable_activity(activity):
    exported = activity.get("{http://schemas.android.com/apk/res/android}exported")
    enabled=activity.get("{http://schemas.android.com/apk/res/android}enabled")
    if enabled is not None and enabled == "false":
        return False
    if exported is None:
        flag=bool(activity.findall("intent-filter"))
        return flag
    return exported.lower() == "true"

def getFileAgentComponents(apk_path):
    res = []

    apk = APK(apk_path)
    manifest = apk.get_android_manifest_xml()

    activities = manifest.findall(".//activity")
    activities.extend(manifest.findall(".//activity-alias"))  # fix bug: no activity-alias
    for activity in activities:
        name = activity.get("{http://schemas.android.com/apk/res/android}name")

        if not is_reachable_activity(activity):
            continue

        fac = FAComponent(name)

        for intent_filter in activity.findall("intent-filter"):
            # actions
            for action in intent_filter.findall("action"):
                action_name = action.get("{http://schemas.android.com/apk/res/android}name")
                if action_name and action_name not in fac.actions:
                    fac.actions.append(action_name)

            # data 节点
            for data in intent_filter.findall("data"):
                scheme = data.get("{http://schemas.android.com/apk/res/android}scheme")
                if scheme and scheme not in fac.dataSchemes:
                    fac.dataSchemes.append(scheme)
                mime = data.get("{http://schemas.android.com/apk/res/android}mimeType")
                if mime and mime not in fac.mimeTypes:
                    fac.mimeTypes.append(mime)
                path_pattern = data.get("{http://schemas.android.com/apk/res/android}pathPattern")
                if path_pattern and path_pattern not in fac.pathPatterns:
                    fac.pathPatterns.append(path_pattern)


        if fac.matchesFilter():
            res.append(fac)

    return res
# ---------------- 单个 APK 处理 ----------------
def process_single_apk(apk_path, output_dir):
    pkg_name = os.path.splitext(os.path.basename(apk_path))[0]
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, f"{pkg_name}.json")
    if os.path.exists(json_path):
        return pkg_name, True, None
    try:
        components = getFileAgentComponents(apk_path)

        facomponents = {}
        for fac in components:
            facomponents[fac.name] = {
                "actions": fac.actions,
                "dataSchemes": fac.dataSchemes,
                "mimeTypes": fac.mimeTypes,
                "pathPatterns": fac.pathPatterns
            }
        if not facomponents:
            return pkg_name, True, None

        json_data = {
            "FAComponent": facomponents,
            "sinkMethod": {}
        }


        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_data, f, indent=4, ensure_ascii=False)

        return pkg_name, True, None
    except Exception as e:
        return pkg_name, False, str(e)

def process_apk_directory_multithread(apk_dir, out_dir, max_workers=4):
    apk_files = [
        os.path.join(apk_dir, f)
        for f in os.listdir(apk_dir)
        if f.endswith(".apk")
    ]

    total = len(apk_files)
    print(f"[INFO] Found {total} APKs to process")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_single_apk, apk_path, out_dir): apk_path for apk_path in apk_files}
        for i, future in enumerate(as_completed(futures), 1):
            pkg_name, success, error = future.result()
            if success:
                print(f"[{i}/{total}] {pkg_name} processed successfully")
            else:
                print(f"[{i}/{total}] ERROR processing {pkg_name}: {error}")

def printComponents(apk_path):
    print(f"[App]:{apk_path}")
    components = getFileAgentComponents(apk_path)
    for fac in components:
        print("="*75)
        print(f"FAComponent: {fac.name}")
        print(f"   actions: {fac.actions}")
        print(f"   dataSchemes: {fac.dataSchemes}")
        print(f"   mimeTypes: {fac.mimeTypes}")
        print(f"   pathPatterns: {fac.pathPatterns}")
    print("="*75)


apk_dir=config.apksDir
out_dir=config.dynamic_input
process_apk_directory_multithread(apk_dir,out_dir)
