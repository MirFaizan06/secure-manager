; VaultKeeper Pro - Inno Setup Installer Script
; This installer properly installs VaultKeeper Pro with user data in writable location

#define MyAppName "VaultKeeper Pro"
#define MyAppVersion "2.0"
#define MyAppPublisher "The NxT LvL"
#define MyAppURL "https://vault-keeper.netlify.app/"
#define MyAppExeName "VaultKeeperPro.exe"

[Setup]
; Unique App ID (GUID)
AppId={{B2C3D4E5-6F7G-8H9I-0J1K-L2M3N4O5P6Q7}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

; Installation directory - User's Local AppData (writable without admin)
DefaultDirName={localappdata}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes

; Output configuration
OutputDir=installers
OutputBaseFilename=VaultKeeperPro_Setup
; Updated to use Windows 10/11 compliant icon from assets folder
; Icon includes all required sizes: 16, 32, 48, 64, 128, 256, 512, 1024
SetupIconFile=assets\app.ico
Compression=lzma2/max
SolidCompression=yes

; Windows version requirements
MinVersion=10.0
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64

; Privileges - don't require admin (installs in user folder)
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

; UI configuration
WizardStyle=modern
DisableWelcomePage=no
LicenseFile=LICENSE

; Uninstall configuration
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
; Main executable
Source: "dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

; Required files
Source: "Features_Pro.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "LICENSE"; DestDir: "{app}"; Flags: ignoreversion

; Windows 10/11 icon assets - included for proper Windows integration
; These ensure correct icon display in all Windows contexts (taskbar, alt-tab, file explorer, etc.)
Source: "assets\app.ico"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "assets\w11_16.png"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "assets\w11_32.png"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "assets\w11_48.png"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "assets\w11_64.png"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "assets\w11_128.png"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "assets\w11_256.png"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "assets\w11_512.png"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "assets\w11_1024.png"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "assets\Square310x310Logo.png"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "assets\Square150x150Logo.png"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "assets\Square71x71Logo.png"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "assets\Square44x44Logo.png"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "assets\Wide310x150Logo.png"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "assets\StoreLogo.png"; DestDir: "{app}\assets"; Flags: ignoreversion
Source: "assets\Small24x24Logo.png"; DestDir: "{app}\assets"; Flags: ignoreversion

[Icons]
; Start Menu icons
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{group}\Features"; Filename: "{app}\Features_Pro.txt"
Name: "{group}\Visit Website"; Filename: "{#MyAppURL}"
Name: "{group}\Get License Key"; Filename: "{#MyAppURL}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"

; Desktop icon (optional, based on task selection)
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Show features after install
Filename: "{app}\Features_Pro.txt"; Description: "View Pro Features"; Flags: postinstall shellexec skipifsilent nowait

; Launch application after install
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

[Code]
var
  DataDirPage: TInputDirWizardPage;

procedure InitializeWizard;
begin
  // Simple welcome page - no custom text needed
  // Default Inno Setup welcome message is clean and simple
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  DataDir: string;
  AppDataDir: string;
begin
  if CurStep = ssPostInstall then
  begin
    // Create data directory in user's Documents folder
    DataDir := ExpandConstant('{userdocs}\VaultKeeper Pro Data');
    if not DirExists(DataDir) then
      CreateDir(DataDir);

    // Create my_documents subfolder
    if not DirExists(DataDir + '\my_documents') then
      CreateDir(DataDir + '\my_documents');

    // AppData directory for auth files is created automatically by the app
    // But we ensure it exists
    AppDataDir := ExpandConstant('{userappdata}\VaultKeeper');
    if not DirExists(AppDataDir) then
      CreateDir(AppDataDir);
  end;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;

  // Check if already installed
  if RegKeyExists(HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{B2C3D4E5-6F7G-8H9I-0J1K-L2M3N4O5P6Q7}_is1') then
  begin
    if MsgBox('VaultKeeper Pro is already installed. Do you want to reinstall?', mbConfirmation, MB_YESNO) = IDNO then
      Result := False;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: string;
  AppDataDir: string;
  Response: Integer;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{userdocs}\VaultKeeper Pro Data');
    AppDataDir := ExpandConstant('{userappdata}\VaultKeeper');

    // Ask user if they want to keep their data
    if DirExists(DataDir) or DirExists(AppDataDir) then
    begin
      Response := MsgBox(
        'Do you want to delete ALL your VaultKeeper data?' + #13#10 + #13#10 +
        'This includes:' + #13#10 +
        '  • All passwords and documents' + #13#10 +
        '  • Master password and security settings' + #13#10 +
        '  • 2FA configuration' + #13#10 +
        '  • License information' + #13#10 + #13#10 +
        'WARNING: This action CANNOT be undone!' + #13#10 + #13#10 +
        'Select "Yes" to DELETE everything' + #13#10 +
        'Select "No" to KEEP all data for future installations',
        mbConfirmation, MB_YESNO or MB_DEFBUTTON2);

      if Response = IDYES then
      begin
        // Delete all data
        if DirExists(DataDir) then
          DelTree(DataDir, True, True, True);

        if DirExists(AppDataDir) then
          DelTree(AppDataDir, True, True, True);

        MsgBox('All VaultKeeper data has been deleted.', mbInformation, MB_OK);
      end
      else
      begin
        MsgBox('Your data has been preserved. You can reinstall VaultKeeper Pro later without losing your data.', mbInformation, MB_OK);
      end;
    end;
  end;
end;
