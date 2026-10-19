# -*- coding:utf-8 -*-
import subprocess
import os
import time
from datetime import datetime
import utils.config as config

def log(msg):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] {msg}")

def run_adb_command(command,timeout=60):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,encoding='utf-8',errors='ignore',timeout=timeout)
        if result.returncode != 0:
            if "android.permission." not in command:
                print("Error info:", result.stderr.strip())
            return "Error!"
        return result.stdout.strip()
    except Exception as e:
        return "Error!"

def build_adb_su_command(shell_command):
    return f"adb shell \"su 0 sh -c '{shell_command}'\""

def get_top_activity():
    command = f'adb shell dumpsys activity top | grep ACTIVITY'
    log(f"Execute search command: {command}")
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        res=result.stdout.strip()
        top_res=res.split('\n')[-1]
        top_res=top_res[:top_res.index('/')].replace(' ','').replace('ACTIVITY','')
        log(f"Get running application: {top_res}")
        return top_res
    else:
        log("Error info: " + result.stderr.strip())
        return ''

def run_adb_with_grep(package_name='', outdir="."):
    try:
        if package_name == '':
            package_name = get_top_activity()
        command = f'adb shell pm list package -f | grep {package_name}'
        log(f"Execute search command: {command}")
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode == 0:
            res = result.stdout.strip()
            path = res[res.index("package:") + len("package:"):res.index(".apk") + 4]
            out_apk = f"/sdcard/{package_name}.apk"

            cp_command = f'adb shell cp "{path}" "{out_apk}"'
            log(f"Execute copy command: {cp_command}")
            subprocess.run(cp_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            pull_command = f'adb pull "{out_apk}" "{outdir}"'
            log(f"Execute pull command: {pull_command}")
            pull_result = subprocess.run(pull_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            if pull_result.returncode == 0:
                log(f"APK has been saved to: {os.path.abspath(outdir)}")

                rm_command = f'adb shell rm "{out_apk}"'
                log(f"Execute remove command: {rm_command}")
                subprocess.run(rm_command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                log("Pull APK failed, skip remove operation")

        else:
            log("Error info: " + result.stderr.strip())
            return None

    except Exception as e:
        log("Exception occur: " + str(e))
        return None

APK_PATH="/data/local/tmp/demo"

def push_test_apks(apk_dir):
    
    command=build_adb_su_command(f"mkdir -p {APK_PATH}")
    log("Create target APK directory: "+command)
    run_adb_command(command)

    command=build_adb_su_command(f"chmod 777 {APK_PATH}")
    log("Grant target APK directory permission: "+command)
    run_adb_command(command)

    pushed_apks=[]
    for apk in os.listdir(apk_dir):
        if(apk.endswith(".apk")):
            apkPath=os.path.join(apk_dir,apk)
            command=f"adb push {apkPath} {APK_PATH}"
            log("Push APK: "+command)
            res=run_adb_command(command)
            if res!="Error!":
                pushed_apks.append(apk)
    return pushed_apks

def pm_install_apk(apk):
    command=build_adb_su_command(f"pm install {APK_PATH}/{apk}")
    log("Execute install command: "+command)
    res=run_adb_command(command)
    log("Install app: "+res)

def adb_install_apk(apkPath):
    command=f"adb install {apkPath}"
    log("Execute install command: "+command)
    res=run_adb_command(command)
    log("Install app: "+res)

def adb_uninstall_apk(pkg):
    command=build_adb_su_command(f"pm uninstall {pkg}")
    log("Execute remove command: "+command)
    run_adb_command(command)

def pm_install_apkList(apkList):
    for apk in apkList:
        if(apk.endswith(".apk")):
            pm_install_apk(apk)

def uninstall_pkgList(pkgList):
    for pkg in pkgList:
        adb_uninstall_apk(pkg)

def test_app_install_success(pkg):
    command=f"adb shell pm list packages {pkg}"
    res=run_adb_command(command)
    if pkg in res:
        return True
    return False

def get_target_apkList():
    command = build_adb_su_command(f"ls {APK_PATH}")
    log("List target APKs: " + command)
    res = run_adb_command(command)
    res=res.split("\n")
    return res

def clear_local_tmp():
    command = build_adb_su_command(f"rm {APK_PATH}/*.apk")
    log("Remove app installation package: " + command)
    run_adb_command(command)

def check_file_write(package_name:str):
    command=build_adb_su_command(f"cat /data/data/{package_name}/CAFIflag")
    res=run_adb_command(command)
    print("check_file_write: ",res)
    if res and "Attack@CAFI" in res:
        return True
    return False

def check_all_file_write(package_name:str):
    command=build_adb_su_command(f"grep -ra Attack@CAFI /data/data/{package_name} 2>/dev/null")
    res=run_adb_command(command)
    if res and "Attack@CAFI" in res:
        return (True,res.split('\n'))
    command2=build_adb_su_command(f"grep -ra Attack@CAFI /sdcard/Android/data/{package_name} 2>/dev/null")
    res2=run_adb_command(command2)
    if res2 and "Attack@CAFI" in res2:
        return (True,res2.split('\n'))
    return (False,[])

ANDROID_STORAGE_PERMISSIONS = [
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.CAMERA"
]

def grant_all_permissions(pkg):
    for permission in ANDROID_STORAGE_PERMISSIONS:
        try:
            if not permission.endswith("MANAGE_EXTERNAL_STORAGE"):
                command=build_adb_su_command(f"pm grant {pkg} {permission}")
                run_adb_command(command)
            else:
                command = build_adb_su_command(f"appops set {pkg} MANAGE_EXTERNAL_STORAGE allow")
                run_adb_command(command)
        except:
            pass