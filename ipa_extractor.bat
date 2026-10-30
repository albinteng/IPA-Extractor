@echo off
rem Launch IPA Extractor without a console window, or explain how to get Python.
cd /d "%~dp0"
rem A real Python 3.9+ with Tk passes; the Microsoft Store "python" placeholder does not.
python -c "import sys, tkinter; sys.exit(sys.version_info < (3, 9))" >nul 2>nul
if not errorlevel 1 (
    start "" pythonw ipa_extractor.py
    exit /b 0
)
echo.
echo  IPA Extractor needs Python 3.9 or later with tcl/tk.
echo  Download it from https://www.python.org/downloads/
echo  and tick "Add python.exe to PATH" during installation.
echo.
start "" https://www.python.org/downloads/
pause
