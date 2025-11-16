; Inno Setup Script for Secure Manager Pro
; Enhanced version with full GUI wizard

#define MyAppName "Secure Manager Pro"
#define MyAppVersion "2.0"
#define MyAppPublisher "Secure Manager Team"
#define MyAppExeName "SecureManagerPro.exe"
#define MyAppURL "https://github.com/yourusername/securemanager"

[Setup]
; Basic app information
AppId={{B2C3D4E5-F6A7-8901-BCDE-FG2345678901}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

; Installation paths - USER CAN CHOOSE
DefaultDirName={autopf}\SecureManagerPro
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
DisableDirPage=no
DisableProgramGroupPage=no

; Output
OutputDir=installer_output
OutputBaseFilename=SecureManagerPro_Setup_v2.0
Compression=lzma2/max
SolidCompression=yes

; Modern wizard style
WizardStyle=modern
WizardResizable=yes

; Privileges - run as normal user
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

; User interface
SetupIconFile=compiler:SetupClassicIcon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}

; Version info
VersionInfoVersion=2.0.0.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Setup - Password & Document Manager
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion=2.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a Desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked
Name: "startmenu"; Description: "Create Start Menu shortcuts"; GroupDescription: "Additional shortcuts:"; Flags: checkedonce
Name: "quicklaunch"; Description: "Create Quick Launch shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked; OnlyBelowVersion: 6.1

[Files]
; The main executable
Source: "dist\SecureManagerPro.exe"; DestDir: "{app}"; Flags: ignoreversion
; Documentation
Source: "README.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "INSTALLER_README.txt"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "FEATURES.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Start Menu shortcuts (if selected)
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: startmenu
Name: "{group}\README"; Filename: "{app}\README.txt"; Tasks: startmenu
Name: "{group}\Features Guide"; Filename: "{app}\FEATURES.txt"; Tasks: startmenu
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"; Tasks: startmenu

; Desktop shortcut (if selected)
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

; Quick Launch (if selected)
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: quicklaunch

[Run]
; Option to run the app after installation
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Clean up data files on uninstall (after confirmation)
Type: filesandordirs; Name: "{app}\my_documents"
Type: files; Name: "{app}\passwords.enc"
Type: files; Name: "{app}\documents.json"
Type: files; Name: "{app}\secret.key"
Type: files; Name: "{app}\settings.json"

[Code]
// Custom messages and confirmations
function InitializeSetup(): Boolean;
begin
  Result := True;
  MsgBox('Welcome to Secure Manager Pro Setup!' + #13#10 + #13#10 +
         'This installer will guide you through the installation process.' + #13#10 + #13#10 +
         'Features:' + #13#10 +
         '• Encrypted password storage' + #13#10 +
         '• Password generator with strength indicator' + #13#10 +
         '• Document manager' + #13#10 +
         '• Multiple themes (Dark, Light, Neon, Dev, Ocean)' + #13#10 +
         '• Backup & Restore functionality' + #13#10 + #13#10 +
         'Click Next to continue.',
         mbInformation, MB_OK);
end;

function InitializeUninstall(): Boolean;
var
  Response: Integer;
begin
  Response := MsgBox('WARNING: Uninstalling will delete all your saved passwords and documents!' + #13#10 + #13#10 +
                     'Make sure you have created a backup using the app''s Backup feature before continuing.' + #13#10 + #13#10 +
                     'Your data will be permanently deleted!' + #13#10 + #13#10 +
                     'Do you want to continue with uninstallation?',
                     mbConfirmation, MB_YESNO);
  Result := Response = IDYES;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    MsgBox('Installation Complete!' + #13#10 + #13#10 +
           'Important Security Notes:' + #13#10 +
           '• Your data will be stored in: ' + ExpandConstant('{app}') + #13#10 +
           '• BACKUP your secret.key file regularly!' + #13#10 +
           '• Use the built-in Backup feature to save your data' + #13#10 + #13#10 +
           'Click OK to finish.',
           mbInformation, MB_OK);
  end;
end;
