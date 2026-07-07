@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
set "SRC_DIR=%SCRIPT_DIR%..\.."

cd /d "%SRC_DIR%"

echo Running baseline pilot batch...
echo Working directory: %CD%
echo.

conda run -n vulnerability_detection python "%SCRIPT_DIR%run_baseline_pilot.py"

echo.
echo Script finished. Check runs\baseline\baseline_hackatdac_deepseek_gpt_pilot_v1\batch_status.jsonl for per-run status.
pause
