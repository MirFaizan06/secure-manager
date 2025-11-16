@echo off
echo ========================================
echo  Secure Manager - Build Installer
echo ========================================
echo.

echo Step 1: Installing required packages...
python -m pip install --upgrade pip
pip install customtkinter cryptography pyinstaller
echo.

echo Step 2: Building executable with PyInstaller...
pyinstaller secure_manager.spec --clean
echo.

if not exist "dist\SecureManager.exe" (
    echo ERROR: Failed to create executable!
    pause
    exit /b 1
)

echo Step 3: Executable created successfully!
echo Location: dist\SecureManager.exe
echo.

echo Step 4: Creating Windows Installer with Inno Setup...
echo.
echo IMPORTANT: You need to install Inno Setup first!
echo Download from: https://jrsoftware.org/isdl.php
echo.
echo After installing Inno Setup:
echo 1. Open Inno Setup Compiler
echo 2. Click File ^> Open
echo 3. Select: installer_script.iss
echo 4. Click Build ^> Compile
echo.
echo OR if Inno Setup is in PATH, run:
echo "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer_script.iss
echo.

echo ========================================
echo Build process completed!
echo ========================================
echo.
echo What was created:
echo - Executable: dist\SecureManager.exe
echo.
echo Next steps:
echo 1. Test the executable in dist\SecureManager.exe
echo 2. Install Inno Setup (if not already installed)
echo 3. Compile installer_script.iss with Inno Setup
echo 4. Your installer will be in: installer_output\SecureManager_Setup.exe
echo.
pause
