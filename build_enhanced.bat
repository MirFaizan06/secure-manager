@echo off
echo ========================================
echo  Secure Manager Pro - Enhanced Build
echo ========================================
echo.

echo Cleaning previous build...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
if exist "SecureManagerPro.spec" del "SecureManagerPro.spec"
echo.

echo Installing/Updating packages...
pip install --upgrade customtkinter cryptography pyinstaller pillow
echo.

echo Building Secure Manager Pro (this may take a few minutes)...
pyinstaller --clean --noconfirm ^
    --onefile ^
    --windowed ^
    --name "SecureManagerPro" ^
    --hidden-import customtkinter ^
    --hidden-import cryptography.fernet ^
    --hidden-import cryptography.hazmat ^
    --hidden-import cryptography.hazmat.primitives ^
    --hidden-import cryptography.hazmat.backends ^
    --hidden-import PIL ^
    --collect-all customtkinter ^
    secure_manager_enhanced.py

echo.
if exist "dist\SecureManagerPro.exe" (
    echo ========================================
    echo SUCCESS! Executable created!
    echo ========================================
    echo.
    echo Location: dist\SecureManagerPro.exe
    echo Size:
    dir "dist\SecureManagerPro.exe" | find "SecureManagerPro.exe"
    echo.
    echo Test it now? The app will launch...
    pause
    start "" "dist\SecureManagerPro.exe"
) else (
    echo ========================================
    echo ERROR! Build failed.
    echo ========================================
    echo Please check the errors above.
    pause
)
