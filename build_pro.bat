@echo off
echo Building VaultKeeper Pro...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"

pip install --upgrade customtkinter cryptography pyinstaller pillow requests

pyinstaller --clean --noconfirm --onefile --windowed --name "VaultKeeperPro" --hidden-import customtkinter --hidden-import cryptography.fernet --hidden-import cryptography.hazmat --collect-all customtkinter vaultkeeper_pro.py

if exist "dist\VaultKeeperPro.exe" (
    echo SUCCESS! Pro version built: dist\VaultKeeperPro.exe
    echo.
    echo Upload this to Firebase Storage > downloads folder
) else (
    echo BUILD FAILED!
)
pause
