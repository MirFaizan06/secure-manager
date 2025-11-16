@echo off
echo Building VaultKeeper Free...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"

pip install --upgrade customtkinter cryptography pyinstaller pillow

pyinstaller --clean --noconfirm --onefile --windowed --name "VaultKeeperFree" --hidden-import customtkinter --hidden-import cryptography.fernet --collect-all customtkinter vaultkeeper_free.py

if exist "dist\VaultKeeperFree.exe" (
    echo SUCCESS! Free version built: dist\VaultKeeperFree.exe
) else (
    echo BUILD FAILED!
)
pause
