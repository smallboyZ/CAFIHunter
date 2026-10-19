# -*- coding:utf-8 -*-
import argparse

import run
import utils.adbTools as adb
import utils.config as config
import utils.parseReport as parseReport


STEP_INPUT = "input"
STEP_PUSH = "push"
STEP_INSTALL = "install"
STEP_ANALYSE = "analyse"
ALL_STEPS = [STEP_INPUT, STEP_PUSH, STEP_INSTALL, STEP_ANALYSE]


def generate_dynamic_inputs():
    adb.log("Step 0: generate dynamic input from static reports")
    parseReport.generate_dynamic_input_dir(strDir=config.static_records)


def push_apks_to_device():
    adb.log("Step 1: push apks to device")
    adb.log("Local APK directory: " + config.apksDir)
    adb.log("Remote APK directory: " + adb.APK_PATH)
    adb.push_test_apks(config.apksDir)


def install_apks_on_device():
    adb.log("Step 2: install apks from device directory")
    apkList = adb.get_target_apkList()
    adb.pm_install_apkList(apkList)


def run_dynamic_analyse():
    adb.log("Step 3: run dynamic analyse")
    run.runAnalyse()


def run_steps(steps):
    for step in steps:
        if step == STEP_INPUT:
            generate_dynamic_inputs()
        elif step == STEP_PUSH:
            push_apks_to_device()
        elif step == STEP_INSTALL:
            install_apks_on_device()
        elif step == STEP_ANALYSE:
            run_dynamic_analyse()
        else:
            raise ValueError("Unsupported step: " + step)


def parse_args():
    parser = argparse.ArgumentParser(
        description="CAFIHunter dynamic test pipeline"
    )
    parser.add_argument(
        "--steps",
        nargs="+",
        choices=ALL_STEPS,
        default=ALL_STEPS,
        help="Pipeline steps to run. Default: input push install analyse",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run_steps(args.steps)
