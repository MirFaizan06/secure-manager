# VaultKeeper - Secure Password & Document Manager

Professional password manager with military-grade encryption.

## Versions

### Free Version
- Up to 10 passwords
- Up to 5 documents
- Encrypted storage
- Simple interface

### Pro Version ($10/6 months)
- **Military-grade AES-256 encryption**
- **Unlimited password storage**
- **Secure password generator**
- **Master password authentication** (10 characters minimum)
- **Security question password recovery**
- **Two-Factor Authentication (2FA)** - Offline TOTP
- **Zero-Trust security model**
- **Restricted access via password authentication**
- Strength indicator
- 6 premium themes included
- Backup & restore
- Categories & tags
- Priority email support
- 6 months full premium access

## Download

Visit [vault-keeper.netlify.app](https://vault-keeper.netlify.app) to download.

## Features

- 🔐 Fernet encryption (industry standard)
- 📄 Document manager
- 🎨 Multiple themes (Pro)
- 💾 Backup & restore (Pro)
- 🎲 Password generator (Pro)
- 📊 Strength indicator (Pro)

## System Requirements

- Windows 10/11
- 100 MB disk space
- 2 GB RAM

## Security

- **Military-grade AES-256 encryption** via Fernet
- **Master password authentication** - Required on every app launch
- **PBKDF2 password hashing** with 100,000 iterations
- **Security question recovery** - Forgot password? Answer your security question
- **Two-Factor Authentication (2FA)** - Offline TOTP using authenticator apps
  - Compatible with Google Authenticator, Microsoft Authenticator, Authy
  - QR code setup for easy configuration
  - No internet required after setup
- **Secure storage** - Auth files hidden in Windows AppData
- **Zero-Trust architecture** - All data encrypted locally
- Your data never leaves your device
- No cloud sync (your choice)

## License

Proprietary software. See LICENSE file.

## Support

mirfaizan8803@gmail.com

## Building from Source

### Quick Build (Recommended)

Use the unified build script to build both versions with proper icon integration:

```bash
build_all.bat
```

This script will:
1. Clean previous builds
2. Build VaultKeeper Free executable
3. Build VaultKeeper Pro executable
4. Copy Windows 10/11 icons to distribution folders
5. Create installers using Inno Setup (if installed)

### Individual Builds

```bash
# Free version only
build_free.bat

# Pro version only
build_pro.bat
```

### Manual Icon Copy

If you need to copy icons manually after building:

```bash
# Copy icons for both versions
copy_icons_postbuild.bat all

# Copy icons for Free version only
copy_icons_postbuild.bat free

# Copy icons for Pro version only
copy_icons_postbuild.bat pro
```

### Icon Assets

All Windows 10/11 compliant icons are located in the `assets/` folder:

- **app.ico** - Multi-resolution icon (16, 32, 48, 64, 128, 256, 512, 1024px)
- **w11_*.png** - Individual PNG sizes for Windows 11
- **Square*.png** - Windows tile logos (for Microsoft Store)
- **Wide310x150Logo.png** - Wide tile logo
- **StoreLogo.png** - Store listing icon
- **Small24x24Logo.png** - Small tile icon

The icon integration ensures:
- ✅ Proper display in Windows taskbar
- ✅ Correct appearance in Alt+Tab switcher
- ✅ High-quality icons in File Explorer
- ✅ Sharp rendering on high-DPI displays
- ✅ Windows 10 and Windows 11 compliance

### Build Requirements

- Python 3.x
- PyInstaller (`pip install pyinstaller`)
- All dependencies from `requirements.txt`
- Inno Setup 6 (optional, for creating installers)

### Build Output

After building, you'll find:

- `dist/VaultKeeperFree.exe` - Free version executable
- `dist/VaultKeeperPro.exe` - Pro version executable
- `dist/assets/` - Icon assets folder
- `installers/VaultKeeperFree_Setup.exe` - Free installer (if Inno Setup installed)
- `installers/VaultKeeperPro_Setup.exe` - Pro installer (if Inno Setup installed)

## Copyright

© 2025 The NxT LvL. All Rights Reserved.

**This software is proprietary. Unauthorized distribution is prohibited.**
