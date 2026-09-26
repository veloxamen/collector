@echo off
REM Launches collector.exe with administrator privileges.
REM Uncomment and modify ARGS='' when options are needed

setlocal
set "EXE_DIR=%~dp0"
set "EXE_PATH=%EXE_DIR%collector.exe"
REM set "ARGS='-mem -hash -json-report'"

if not exist "%EXE_PATH%" (
    echo [ERROR] collector.exe not found next to run_elevated.bat: %EXE_PATH%
    pause
    exit /b 1
)

powershell -NoProfile -Command ^
    "Start-Process -FilePath '%EXE_PATH%' %ARGS% -WorkingDirectory '%EXE_DIR%' -Verb RunAs"

endlocal
