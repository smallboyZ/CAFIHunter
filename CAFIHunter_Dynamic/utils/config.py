# -*- coding:utf-8 -*-
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PROJECT_ROOT.parent

apksDir = r"C:\path\to\apks"


static_records = str(REPO_ROOT / "CAFIHunter_Static" / "out" / "data_use_info")
dynamic_input = str(PROJECT_ROOT / "dynamic_input")
dynamic_output = str(PROJECT_ROOT / "dynamic_output")
dynamic_out = dynamic_output
final_pocs = str(PROJECT_ROOT / "vulns" / "pocs.json")
testLog = str(PROJECT_ROOT / "CAFILog.json")
payload_repo = str(PROJECT_ROOT / "dataset" / "payload_repo.json")
