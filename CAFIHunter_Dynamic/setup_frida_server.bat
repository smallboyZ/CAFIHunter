@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "PROJECT_DIR=%~dp0"
set "FRIDA_DIR=%PROJECT_DIR%frida-server-16.6.6"
set "REMOTE_TMP=/data/local/tmp"
set "REMOTE_DIR=/data/adb"

where adb >nul 2>nul
if errorlevel 1 (
    echo [ERROR] adb not found in PATH.
    exit /b 1
)

echo [INFO] Check connected adb device...
adb get-state >nul 2>nul
if errorlevel 1 (
    echo [ERROR] No adb device connected. Please run adb devices -l first.
    adb devices -l
    exit /b 1
)

for /f "usebackq delims=" %%A in (`adb shell getprop ro.product.cpu.abi`) do (
    set "ABI=%%A"
    goto :got_abi
)
:got_abi
set "ABI=%ABI: =%"

if "%ABI%"=="" (
    echo [ERROR] Failed to detect device ABI.
    exit /b 1
)

echo [INFO] Device ABI: %ABI%

set "LOCAL_FRIDA="
set "FRIDA_NAME="

if /i "%ABI%"=="arm64-v8a" (
    set "FRIDA_NAME=frida-server-16.6.6-android-arm64-AE"
    set "LOCAL_FRIDA=%FRIDA_DIR%\arm64\!FRIDA_NAME!"
) else if /i "%ABI%"=="armeabi-v7a" (
    set "FRIDA_NAME=frida-server-16.6.6-android-arm"
    set "LOCAL_FRIDA=%FRIDA_DIR%\arm\!FRIDA_NAME!"
) else if /i "%ABI%"=="armeabi" (
    set "FRIDA_NAME=frida-server-16.6.6-android-arm"
    set "LOCAL_FRIDA=%FRIDA_DIR%\arm\!FRIDA_NAME!"
) else if /i "%ABI%"=="x86" (
    set "FRIDA_NAME=frida-server-16.6.6-android-x86"
    set "LOCAL_FRIDA=%FRIDA_DIR%\x86\!FRIDA_NAME!"
) else if /i "%ABI%"=="x86_64" (
    set "FRIDA_NAME=frida-server-16.6.6-android-x86_64"
    set "LOCAL_FRIDA=%FRIDA_DIR%\x86_64\!FRIDA_NAME!"
) else (
    echo [ERROR] Unsupported ABI: %ABI%
    echo [INFO] Supported ABI: arm64-v8a, armeabi-v7a, armeabi, x86, x86_64
    exit /b 1
)

if not exist "!LOCAL_FRIDA!" (
    echo [ERROR] Frida server file not found: !LOCAL_FRIDA!
    exit /b 1
)

echo [INFO] Selected Frida server: !LOCAL_FRIDA!

echo [INFO] Create remote directory: %REMOTE_DIR%
adb shell "su 0 sh -c 'mkdir -p %REMOTE_DIR%'"
if errorlevel 1 exit /b 1

echo [INFO] Push to %REMOTE_TMP%/!FRIDA_NAME!
adb push "!LOCAL_FRIDA!" "%REMOTE_TMP%/!FRIDA_NAME!"
if errorlevel 1 exit /b 1

echo [INFO] Copy to %REMOTE_DIR%/!FRIDA_NAME!
adb shell "su 0 sh -c 'cp %REMOTE_TMP%/!FRIDA_NAME! %REMOTE_DIR%/!FRIDA_NAME!'"
if errorlevel 1 exit /b 1

echo [INFO] chmod +x %REMOTE_DIR%/!FRIDA_NAME!
adb shell "su 0 sh -c 'chmod +x %REMOTE_DIR%/!FRIDA_NAME!'"
if errorlevel 1 exit /b 1

echo [INFO] Stop existing frida-server if any...
adb shell "su 0 sh -c 'pkill -f frida-server 2>/dev/null || true'" >nul 2>nul

echo [INFO] Start Frida server...
adb shell "su 0 sh -c 'nohup %REMOTE_DIR%/!FRIDA_NAME! >/dev/null 2>&1 &'"
if errorlevel 1 exit /b 1

timeout /t 1 /nobreak >nul

echo [INFO] Check Frida server process:
adb shell "su 0 sh -c 'ps -A | grep frida || ps | grep frida'"

echo [INFO] Done.
endlocal
