@echo off
REM Build notyours into a standalone windowed app that behaves like `python detector.py`.
REM Uses --onedir (not --onefile) so config.json / exports/ are written next to the exe
REM and survive between runs, exactly like the script writes next to itself.
setlocal

set SRC=detector.py
if not exist "%SRC%" (
    echo ERROR: detector.py not found in the current directory.
    exit /b 1
)

if not exist "notyours2.png" (
    echo WARNING: notyours2.png not found; the tray/title-bar logo will be skipped.
)

if not exist "notyours.ico" (
    echo WARNING: notyours.ico not found; the exe will use PyInstaller's default icon.
)

python -m PyInstaller -y --noconsole --onedir --clean --name notyours --icon "notyours.ico" --add-data "notyours2.png;." --hidden-import pystray._win32 --hidden-import pystray._util --hidden-import pystray._util.win32 %SRC%

echo.
if exist "dist\notyours\notyours.exe" (
    echo Build complete: dist\notyours\notyours.exe
) else (
    echo Build finished, but dist\notyours\notyours.exe was not found. Check output above.
)
endlocal
