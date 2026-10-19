# -*- coding:utf-8 -*-
import os
import time
import traceback
import utils.poc_generator as poc_gen
import utils.analyzeTools as analyze
import utils.adbTools as adb
import utils.fridaTools as myfrdia
import utils.parseReport as parseReport
import utils.config as config
import utils.fridaTools as fridaTools
import AutoTest.autoTest as atTest


class CAFIHunter:
    def __init__(self,script,d):
        self.script=script
        self.d=d
        self.payloads={}

    def load_payloads(self):
        try:
            adb.log("Load payload repository")
            self.payloads=parseReport.getJsonData(config.payload_repo)
        except Exception as e:
            adb.log("Load payload repository failed")
    def save_payloads(self):
        try:
            adb.log("Optimize payload repository")
            parseReport.saveJsonData(self.payloads,config.payload_repo)
        except Exception as e:
            adb.log("Load payload repository failed")

    def runAnalyse(self):
        testedApk=parseReport.getJsonData(config.testLog).keys()

        apkList=adb.get_target_apkList()
        pkgList=[]
        for apk in apkList:
            if apk.endswith('.apk') and apk[:-4] not in testedApk:
                pkgList.append(apk[:-4])
        if len(pkgList)==0:
            print("All apps have been analysed ;-)")

        parseReport.generate_dynamic_input(pkgList)

        for pkg in pkgList:
            self.runAnalyse_pkg(pkg)
            time.sleep(10)


    def runAnalyse_pkgList(self,pkgList):

        testedApk = parseReport.getJsonData(config.testLog).keys()


        for pkg in pkgList:
            if pkg not in testedApk:
                if self.runAnalyse_pkg(pkg):
                    time.sleep(10)

    def runAnalyse_pkg(self,pkg):
        adb.log(f"Start Analysis: {pkg}")
        start_time = time.time()
        appInstall=adb.test_app_install_success(pkg)
        if not appInstall:
            adb.log("APP is not installed")
            parseReport.saveJsonData({pkg: "-3"}, config.testLog)
            return False

        step=4
        dynamic_input=poc_gen.get_dynamic_input(pkg)
        if not isinstance(dynamic_input, dict) or not dynamic_input:
            adb.log("Analysis failed, no specified dynamic input")
            parseReport.saveJsonData({pkg: "-2"}, config.testLog)
            return False

        FAComponents=dynamic_input['FAComponent'].keys()
        if len(FAComponents) == 0:
            adb.log("Analysis failed; no exposed file import component")
            parseReport.saveJsonData({pkg: "-2"}, config.testLog)
            return False

        pocTemplates=poc_gen.build_constraint_aware_template(dynamic_input)

        adb.log("pocTemplates: ")
        print(pocTemplates)

        self.load_payloads()

        payloads = sorted(
            self.payloads,
            key=self.payloads.get,
            reverse=True
        )

        adb.grant_all_permissions(pkg)
        adb.log("Grant all external storage permissions")

        round_map={}
        record= {
            "query_keys": [],
             "open_pocs": [],
             "call_getType": False,
             "file_paths": [],
             'poc_templates': pocTemplates,
             'dynamic_poc_templates': [],
             'matched_payload':""
        }
        pocs_num=0

        global_openfile_flag=False
        outPath = os.path.join(config.dynamic_out, pkg + ".json")

        max_poc_num=len(FAComponents)*200

        for i in range(0,len(payloads),step):

            round=i//step

            round_payloads=payloads[i:i+step]

            if round==0:
                round_payloads.insert(0,"CAFIflag")

            dynamic_poc_templates = record['dynamic_poc_templates']

            if len(dynamic_poc_templates)==0:
                pocIntents = poc_gen.generate_pocs(pkg,dynamic_input,pocTemplates,round_payloads)
            else:
                pocIntents = poc_gen.generate_pocs_from_dynamic_templates(pkg,dynamic_input,dynamic_poc_templates,round_payloads)

            if len(pocIntents)==0:
                continue

            adb.log(f"Round {round}: execute {len(pocIntents)} pocs!")

            round_map[round]={
                "poc_size":0,
                "open_file_flag":False
            }

            try:
                adb.log("!dynamic_record_init!")
                fridaTools.dynamic_record_init()

                severe_poc,pocid=analyze.analyze_apk_dynamic(self.script,self.d,pkg,pocIntents,round)

                open_file_flag=fridaTools.get_open_file_flag()
                feedback = fridaTools.get_dynamic_record()
                feedback_open_pocs=feedback["open_pocs"]


                if len(feedback_open_pocs)!=0:
                    dynamic_poc_templates.extend(poc_gen.extract_poc_template_from_feedback(pkg,feedback_open_pocs,round_payloads))
                    dynamic_poc_templates=poc_gen.unique(dynamic_poc_templates)
                    record['dynamic_poc_templates']=dynamic_poc_templates

                round_map[round]["poc_size"]=len(pocIntents)
                round_map[round]["open_file_flag"] = open_file_flag

                if not global_openfile_flag:
                    global_openfile_flag=global_openfile_flag or open_file_flag

                record=poc_gen.merge_record(record,feedback)

                if severe_poc:
                    parseReport.saveJsonData({pkg: severe_poc}, config.final_pocs)
                    parseReport.saveJsonData({pkg: "101"}, config.testLog)

                    for tp in sorted(round_payloads,key=len,reverse=True):
                        if tp.format(pkg=pkg) in severe_poc[2]:
                            record['matched_payload']=tp
                            if tp in self.payloads:
                                self.payloads[tp]+=1
                                self.save_payloads()
                                break

                    flag, res = adb.check_all_file_write(pkg)
                    if flag:
                        record['file_paths'].extend(res)
                        record['file_paths']=poc_gen.unique(record['file_paths'])
                    pocs_num+=pocid
                    record['pocs_num']=pocs_num
                    record['cost_time']=time.time() - start_time
                    record['round_map'] = round_map
                    parseReport.saveJsonData(record, outPath)
                    return True

                else:
                    adb.log(f"get_open_file_flag: {open_file_flag}")
                    if open_file_flag:
                        flag, res = adb.check_all_file_write(pkg)
                        adb.log(f"check_all_file_write: {flag}")
                        if flag:
                            record['file_paths'].extend(res)


            except Exception as e:
                parseReport.saveJsonData({pkg:"-1"},config.testLog)
                parseReport.saveJsonData(record, outPath)
                traceback.print_exc()
                return False

            pocs_num+=len(pocIntents)
            record['pocs_num'] = pocs_num
            record['round_map'] = round_map

            parseReport.saveJsonData(record, outPath)

            if round>2 and global_openfile_flag:
                break

            if round==0 and not global_openfile_flag:
                break

            if pocs_num>max_poc_num:
                break

        if len(record["file_paths"]):
            parseReport.saveJsonData({pkg: "100"}, config.testLog)
        else:
            parseReport.saveJsonData({pkg:"0"}, config.testLog)

        record['cost_time'] = time.time() - start_time
        parseReport.saveJsonData(record, outPath)

        return True

    def runPmInstall_pkgs(self):
        apkList=adb.get_target_apkList()
        adb.pm_install_apkList(apkList)

    def runAdbInstall_apks(self,apkDir):
        apkList=os.listdir(apkDir)
        for apk in apkList:
            apkPath=os.path.join(apkDir,apk)
            adb.adb_install_apk(apkPath)

    def clear_APKs(self):
        apkList=adb.get_target_apkList()
        for apk in apkList:
            if apk.endswith('.apk'):
                adb.adb_uninstall_apk(apk[:-4])
        adb.clear_local_tmp()

    def uninstall_pkgList(self,pkgList):
        for pkg in pkgList:
            adb.adb_uninstall_apk(pkg)

    def push_APKs(self):
        apk_dir=config.apksDir
        if not os.path.isdir(apk_dir):
            adb.log("APK directory does not exist: "+apk_dir)
            return 
        adb.push_test_apks(apk_dir)

def runAnalyse():
    try:
        adb.log("Initialize uiautomator2")
        d=atTest.connect_uiautomator2()

        adb.log("Initialize PoC Agent")
        d.app_start("com.poc.agent")
        # d.app_start("com.lab.testpoc")

        adb.log("Initialize frida")
        script=myfrdia.frida_init(d.serial)
        checker=CAFIHunter(script,d)

        # # 1. push apks to devices /data/local/tmp/demo
        # checker.push_APKs()
        
        # #2. install apks 
        # checker.runPmInstall_pkgs()

        #3. run dynamic analyse
        checker.runAnalyse()

        #4. remove apks 
        # checker.clear_APKs()

        adb.log("Analyze Finished")
    except Exception as e:
        print(e)

if __name__ == '__main__':
    runAnalyse()
    pass
