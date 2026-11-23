@echo off
rem Launch IPA Extractor without a console window, or explain how to get Python.
rem The window needs Python 3.10+ with PySide6; the command line (any argument) needs Python 3.10+ only.
rem A real Python passes; the Microsoft Store "python" placeholder does not.
if not "%~1"=="" goto cli
python -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul
if errorlevel 1 goto missing
python -c "import PySide6.QtWidgets" >nul 2>nul
if errorlevel 1 goto getqt
cd /d "%~dp0"
start "" pythonw ipa_extractor.py
exit /b 0
:cli
rem Run where it was called from, so that relative paths keep their meaning.
python -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul
if errorlevel 1 goto missing
python "%~dp0ipa_extractor.py" %*
exit /b %errorlevel%
:getqt
echo.
echo  The window of IPA Extractor needs PySide6 (about 100 MB).
choice /m "Install it now with pip"
if errorlevel 2 exit /b 1
python -m pip install PySide6-Essentials
if errorlevel 1 (
    pause
    exit /b 1
)
cd /d "%~dp0"
start "" pythonw ipa_extractor.py
exit /b 0
:missing
echo.
echo  IPA Extractor needs Python 3.10 or later.
echo  Download it from https://www.python.org/downloads/
echo  and tick "Add python.exe to PATH" during installation.
echo.
start "" https://www.python.org/downloads/
pause
exit /b 1
