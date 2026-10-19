# CAFIHunter

**The source code of [NDSS 2027] *Inviting the Wolf In: Uncovering the Hidden Risks of Cross-App File Import in Android*.**

CAFIHunter automatically detects and validates Cross-App File Injection (CAFI) in Android applications.

## Overview

CAFIHunter consists of three stages:

1. **File Import Request Inference**: CAFIHunter uses static program analysis to identify exposed file-import components and extract required parameters and validation constraints.
2. **Constraint-aware PoC Generation**: CAFIHunter constructs file-import requests and generates and mutates candidate PoCs according to the extracted constraints.
3. **Dynamic Exploitation**: CAFIHunter dynamically executes candidate PoCs and monitors the exploitation status to determine whether file injection succeeds.

![CAFIHunter](https://pic-1309321804.cos.ap-shanghai.myqcloud.com/images/CAFIHunter.png)

## Project Structure

~~~text
CAFIHunter/
├── CAFIHunter_Static/
│   ├── src/main/java/
│   │   ├── analyze/
│   │   │   └── MainAnalyze.java              # Static-analysis CLI entry point
│   │   ├── component/
│   │   │   ├── ResolveManifest.java          # Manifest, component, and reachability analysis
│   │   │   ├── EntryPointAnalyze.java        # Entry-point extraction
│   │   │   └── FAComponent.java              # Model for cross-app-triggerable components
│   │   ├── cg/
│   │   │   └── CallGraphUtils.java           # Call-graph construction and traversal
│   │   ├── constant/                          # Static-analysis definitions and constants
│   │   ├── dataflow/
│   │   │   ├── FileAgentVulnDetector.java    # CAFI static-analysis workflow orchestrator
│   │   │   ├── CAFIVulnDetector.java         # CAFI detection for an individual APK
│   │   │   ├── FileAgentChecker.java         # File-access sink checker
│   │   │   └── DataFlowEngine.java           # Data-flow analysis engine
│   │   └── util/
│   │       ├── SootInit.java                 # Soot Android-analysis environment initialization
│   │       └── Log.java                      # Static-analysis logging
│   ├── sinks/
│   │   └── FileSink.txt                      # File-access sink methods
│   ├── config.properties                     # Static-analysis configuration
│   ├── pom.xml                               # Maven build configuration
│   ├── lib/                                  # Bundled analysis dependencies
│   └── out/                                  # Static-analysis output directory
│
├── CAFIHunter_Dynamic/
│   ├── dynamic_pipeline.py                   # Dynamic-analysis pipeline entry point
│   ├── run.py                                # Dynamic-analysis main workflow
│   ├── requirements.txt                      # Python dependencies
│   ├── setup_frida_server.bat                # Windows and ADB Frida Server setup script
│   ├── setup_frida_server.sh                # Linux and ADB Frida Server setup script
│   ├── Frida_js/
│   │   └── sendIntent.js                     # Frida Intent-sending script
│   ├── AutoTest/
│   │   └── autoTest.py                       # UI automation for privacy and authorization pages
│   ├── utils/
│   │   ├── config.py                         # Dynamic-analysis paths and APK-directory configuration
│   │   ├── adbTools.py                       # ADB operations, installation, permissions, and result checking
│   │   ├── fridaTools.py                     # Frida initialization and message-feedback handling
│   │   ├── analyzeTools.py                   # Dynamic PoC execution and UI exploration
│   │   ├── parseReport.py                    # Static-report parsing
│   │   ├── poc_generator.py                  # Intent PoC generation
│   │   ├── poc_mutator.py                    # Payload constraint handling and mutation
│   │   ├── getFAVComponents.py               # Lightweight file-import component extraction
│   │   └── runTools.py                       # Timeout execution utilities
│   ├── dataset/
│   │   └── payload_repo.json                 # Payload repository
│   ├── dynamic_input/                        # Dynamic inputs converted from static reports
│   ├── dynamic_output/                       # Dynamic-execution records
│   ├── vulns/                                # Vulnerability output directory
│   ├── CAFILog.json                          # APK analysis status records
│   └── frida-server-16.6.6/                  # Frida Servers for different Android ABIs
│       ├── arm/
│       ├── arm64/
│       ├── x86/
│       └── x86_64/
│
├── PocAgent/
│   ├── app/src/main/java/com/poc/agent/
│   │   ├── MainActivity.java                 # Helper application UI
│   │   └── EvilProvider.java                 # Test ContentProvider
│   ├── app/src/main/AndroidManifest.xml      # Provider authority and export configuration
│   ├── gradle/wrapper/                       # Gradle Wrapper files
│   ├── build.gradle.kts                      # Gradle build configuration
│   ├── gradle.properties                     # Gradle properties
│   ├── local.properties                      # Local Android SDK configuration
│   ├── settings.gradle.kts                   # Gradle project settings
│   └── gradlew / gradlew.bat                 # Gradle Wrapper scripts
~~~

## Requirements

### Hardware

- Windows or Linux;
- a rooted Android device or emulator.

### Software

- Java 8 or later;
- Python 3.9 or 3.10;
- Android SDK Platform Tools;
- Frida 16.6.6;
- Android SDK platforms for static analysis;

## Installation

### 1. Install Python dependencies

Windows (PowerShell):

~~~powershell
cd CAFIHunter_Dynamic
py -3.9 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r .\requirements.txt
python -m uiautomator2 init
~~~

Linux:

~~~bash
cd CAFIHunter_Dynamic
python3.9 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m uiautomator2 init
~~~

### 2. Install PocAgent

If a usable PocAgent APK is available, install it directly:

~~~bash
adb install -r PocAgent.apk
~~~

Otherwise, build it from the included Android project:

Windows:

~~~powershell
cd PocAgent
.\gradlew.bat assembleDebug
adb install -r app\build\outputs\apk\debug\app-debug.apk
~~~

Linux:

~~~bash
cd PocAgent
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
~~~

When building PocAgent, you may need to create or update `PocAgent/local.properties` and set the path to the Android SDK:

~~~properties
sdk.dir=C:\\Users\\<user>\\AppData\\Local\\Android\\Sdk
~~~

Replace the path with the Android SDK path on your system.

## Configuration

### 1. Static-analysis configuration

Edit `CAFIHunter_Static/config.properties`:

~~~properties
apkDir=C:\\path\\to\\apks
androidJar=C:\\Users\\<user>\\AppData\\Local\\Android\\Sdk\\platforms
sinkInfo=sinks\\FileSink.txt
dataSavedDir=out
logFileName=out\\log.txt
analyzeTimeOut=1200
~~~

### 2. APK-directory configuration

Edit `CAFIHunter_Dynamic/utils/config.py`:

~~~python
apksDir = r"C:\path\to\apks"       # Windows
~~~

By default, the dynamic module uses the following directories. You can also customize these paths manually in `CAFIHunter_Dynamic/utils/config.py`:

~~~text
CAFIHunter_Static/out/data_use_info  # Static-analysis reports
CAFIHunter_Dynamic/dynamic_input     # Dynamic inputs
CAFIHunter_Dynamic/dynamic_output    # Dynamic results
CAFIHunter_Dynamic/vulns/pocs.json   # Generated PoCs
CAFIHunter_Dynamic/CAFILog.json      # Analysis status
~~~

### 3. Deploy Frida Server

Connect the Android device or emulator first:

~~~bash
adb devices -l
~~~

Windows:

~~~powershell
cd CAFIHunter_Dynamic
.\setup_frida_server.bat
~~~

Linux:

~~~bash
cd CAFIHunter_Dynamic
chmod +x setup_frida_server.sh
./setup_frida_server.sh
~~~

The setup scripts automatically select a Frida server according to the device ABI.

You can also download the corresponding `frida-server` binary from the [Frida 16.6.6 release](https://github.com/frida/frida/releases?page=12#release-16.6.6) according to your device ABI.

If you prefer to set up Frida manually, first check the device ABI and select the matching local binary:

| Device ABI | Local Frida server |
| --- | --- |
| `arm64-v8a` | `frida-server-16.6.6/arm64/frida-server-16.6.6-android-arm64-AE` |
| `armeabi-v7a` or `armeabi` | `frida-server-16.6.6/arm/frida-server-16.6.6-android-arm` |
| `x86` | `frida-server-16.6.6/x86/frida-server-16.6.6-android-x86` |
| `x86_64` | `frida-server-16.6.6/x86_64/frida-server-16.6.6-android-x86_64` |

~~~bash
adb devices -l
adb shell getprop ro.product.cpu.abi
~~~

The following example uses the `arm64-v8a` binary. Replace the local path with the binary that matches your device ABI:

~~~bash
adb push frida-server-16.6.6/arm64/frida-server-16.6.6-android-arm64-AE /data/local/tmp/frida-server
adb shell "su 0 sh -c 'cp /data/local/tmp/frida-server /data/adb/frida-server'"
adb shell "su 0 sh -c 'chmod 755 /data/adb/frida-server'"
adb shell "su 0 sh -c 'pkill -f frida-server 2>/dev/null || true'"
adb shell "su 0 sh -c '/data/adb/frida-server'"
adb shell "su 0 sh -c 'ps -A | grep frida || ps | grep frida'"
~~~

## Usage

### 1. Run static analysis

The repository provides a prebuilt JAR. You can run it from the project directory:

~~~bash
cd CAFIHunter_Static
java -jar CAFIHunter-1.0.jar -c config.properties
~~~


For large APK collections, more heap memory can be allocated:

~~~bash
java -Xms32G -Xmx128G -jar CAFIHunter-1.0.jar -c config.properties
~~~

Static-analysis reports are generated under:

~~~text
CAFIHunter_Static/out/data_use_info/*.txt
~~~

If the static-analysis module does not generate dynamic input for an APK, run the following lightweight extractor to identify file-import components and generate the corresponding dynamic-input JSON:

~~~bash
cd CAFIHunter_Dynamic/utils
python getFAVComponents.py
~~~

If you want to rebuild the static-analysis module from source, install Maven and run:

~~~bash
cd CAFIHunter_Static
mvn clean package
~~~

Maven generates the executable JAR at:

~~~text
CAFIHunter_Static/target/CAFIHunter-1.0.jar
~~~ 

### 2. Run dynamic analysis

Enter the dynamic-module directory and run:

~~~bash
cd CAFIHunter_Dynamic
python dynamic_pipeline.py
~~~

The pipeline contains the following steps:

| Step | Description |
| --- | --- |
| `input` | Convert static-analysis reports into dynamic-input JSON files |
| `push` | Push APKs to the device |
| `install` | Install APKs on the device |
| `analyse` | Generate PoCs and perform dynamic validation |

The steps can also be executed separately:

~~~bash
python dynamic_pipeline.py --steps input
python dynamic_pipeline.py --steps push
python dynamic_pipeline.py --steps install
python dynamic_pipeline.py --steps analyse
~~~

## Outputs

~~~text
CAFIHunter_Static/out/data_use_info/*.txt   # Static-analysis reports
CAFIHunter_Dynamic/dynamic_input/*.json     # Dynamic inputs
CAFIHunter_Dynamic/dynamic_output/*.json    # Dynamic execution records
CAFIHunter_Dynamic/vulns/pocs.json          # Detected vulnerability PoCs
CAFIHunter_Dynamic/CAFILog.json             # Analysis status
~~~

Common status values:

| Status | Meaning |
| --- | --- |
| `101` | A file can be further injected into an arbitrary path |
| `100` | A file was successfully injected |
| `0` | No successful file injection was observed |
| `-1` | An exception occurred during dynamic analysis |
| `-2` | Dynamic input or candidate components are missing |
| `-3` | The target APK is not installed |

## Ethics and Legal Notice

Test only applications and devices that you own or are authorized to assess.
Comply with applicable laws and your organization's policies.
Report findings responsibly.

