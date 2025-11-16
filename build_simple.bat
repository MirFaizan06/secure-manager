@echo off
echo ========================================
echo  Secure Manager - Simple Build
echo ========================================
echo.

echo Cleaning previous build...
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
echo.

echo Installing/Updating packages...
pip install --upgrade customtkinter cryptography pyinstaller pillow
echo.

echo Building executable (this may take a few minutes)...
pyinstaller --clean --noconfirm ^
    --onefile ^
    --windowed ^
    --name "SecureManager" ^
    --hidden-import customtkinter ^
    --hidden-import cryptography.fernet ^
    --hidden-import PIL ^
    --collect-all customtkinter ^
    secure_manager.py

echo.
if exist "dist\SecureManager.exe" (
    echo ========================================
    echo SUCCESS! Executable created!
    echo ========================================
    echo.
    echo Location: dist\SecureManager.exe
    echo.
    echo Test it now? The app will launch...
    pause
    start "" "dist\SecureManager.exe"
) else (
    echo ========================================
    echo ERROR! Build failed.
    echo ========================================
    echo Please check the errors above.
    pause
)
