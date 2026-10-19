# -*- coding:utf-8 -*-
import time

from AutoTest.autoTest import *
from utils.fridaTools import *
from utils.runTools import *
import utils.fridaTools as fridaTools

POC_APK_PKG="com.poc.agent"

def agree_jump(d):
    if d(text="始终允许打开").exists:
        d(text="始终允许打开").click()
        time.sleep(1)
        d.click(0.716, 0.913)

def send_poc_intent(script,d,poc):
    d.app_start(POC_APK_PKG)
    time.sleep(1)
    log(f"start poc: {poc}")
    if poc[-1].endswith(".SEND"):
        script.exports_sync.sendshare(poc[0],poc[1],poc[2],poc[3],poc[4])
    elif poc[-1].endswith(".VIEW"):
        script.exports_sync.sendview(poc[0],poc[1],poc[2],poc[3],poc[4])
    else:
        script.exports_sync.sendview(poc[0], poc[1], poc[2], poc[3], poc[4])
    agree_jump(d)

def ui_exploration(script,d,pkg):
    log(f"Start target app: {pkg}")
    d.app_start(pkg)
    time.sleep(1)
    log("Dynamic explore page")
    run_with_timeout_TP(handle_privacy_page_dfs, d, 0, timeout=60)
    pass

def analyze_apk_dynamic(script,d,pkg,pocs,round):
    severe_poc=None
    pocid=0
    if round==0:
        ui_exploration(script,d,pkg)

    d.app_start(pkg)
    time.sleep(1)
    severe_flag=check_file_write(pkg)
    log(f"severe_flag: {severe_flag}")
    log(f"pocIntent size: {len(pocs)}")

    for i in range(0,len(pocs)):
        pocid+=1
        poc=pocs[i]
        send_poc_intent(script,d,poc)
        time.sleep(3)
        severe_flag=check_file_write(pkg)
        if severe_flag:
            log(f"Exploitation success; poc: {poc}")
            severe_poc=poc
            break

        time.sleep(1)
    else:
        log(f"poc test complete！")

    d.app_stop(pkg)

    return (severe_poc,pocid)