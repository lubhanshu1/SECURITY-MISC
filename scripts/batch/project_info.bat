@echo off
setlocal

echo SECURITY-MISC :: Project Information
echo ====================================

echo.
echo Current directory:
cd

echo.
echo Git version:
git --version 2>nul

if errorlevel 1 (
    echo Git: not available
)

echo.
echo Python version:
python --version 2>nul

if errorlevel 1 (
    echo Python: not available
)

echo.
echo Project files:
dir /b

echo.
echo Mode: READ-ONLY

endlocal