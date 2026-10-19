# -*- coding:utf-8 -*-
import os
import re
import time
import subprocess
import uiautomator2 as u2


maxDepth=5

def handle_privacy_page_dfs(d,depth):
    if depth>=maxDepth:
        return
    keywords = ["同意", "跳过", "允许", "接受", "继续", "暂不登录", "同意并继续", "知道", "下一步", "关闭",
                "Agree", "Accept", "Allow", "Continue", "Next", "OK", "Got it", "Skip",
                "Not now", "Close", "Confirm","Consent"]
    bad_keywords=["用户协议","隐私政策","服务协议","\n","不","拒绝",
         "disagree", "decline", "not accept", "deny", "reject"
         ]

    nodes=[]
    visitedId = []

    for kw in keywords:
        for node in d.xpath("//*").all():
            node_type=node.info.get("className", "")
            resourceId=node.info.get("resourceId")
            if node.info.get("clickable", False):
                text = node.text
                desc = node.info.get("contentDescription")
                if text and re.search(kw, text,re.IGNORECASE):
                    if any(bad in text.lower() for bad in bad_keywords):
                        continue
                    if resourceId not in visitedId:
                        nodes.append(node)
                        if visitedId:
                            visitedId.append(resourceId)
                if desc and re.search(kw, desc,re.IGNORECASE):
                    if any(bad in desc.lower() for bad in bad_keywords):
                        continue
                    if resourceId not in visitedId:
                        nodes.append(node)
                        if visitedId:visitedId.append(resourceId)
                if resourceId and (("agree" in resourceId and "disagree" not in resourceId) or "close" in resourceId or "not_now" in resourceId):
                    if resourceId not in visitedId:
                        nodes.append(node)
                        visitedId.append(resourceId)
    for node in nodes:
        print(f"Text: {node.text} | Desc: {node.info.get('contentDescription')} | ResID: {node.info.get('resourceId')}")
        node.click()
        time.sleep(1)
        d.dump_hierarchy()
        handle_privacy_page_dfs(d,depth+1)

def get_adb_devices():
    result = subprocess.run(
        ["adb", "devices"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    devices = []
    for line in result.stdout.splitlines():
        if not line.strip() or line.startswith("List of devices"):
            continue
        serial, state = line.rsplit(None, 1)
        if state == "device":
            devices.append(serial.strip())
    return devices

def connect_uiautomator2():
    for attempt in range(5):
        devices = get_adb_devices()

        if devices:
            serial = devices[0]
            print(f"Using Android device: {serial}")
            try:
                os.environ["ANDROID_SERIAL"] = serial
                device = u2.connect(serial)
                _ = device.info
                print("uiautomator2 connected successfully")
                return device
            except Exception as error:
                print(
                    f"Connection failed, retrying "
                    f"({attempt + 1}/5): {error}"
                )
        else:
            print(
                f"No Android device found, retrying "
                f"({attempt + 1}/5)..."
            )

        time.sleep(2)
    raise RuntimeError("Failed to connect to any Android device")