@echo off
echo Running 2ms secrets detection...
docker run --rm -v "%cd%":/scan checkmarx/2ms:latest filesystem --path /scan
if %errorlevel% neq 0 (
    echo [ERROR] Secrets detected! Commit blocked by 2ms.
    exit /b 1
)
echo No secrets detected. Commit allowed.