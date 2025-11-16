; Inno Setup Script for Secure Manager
; This creates a professional Windows installer with full GUI wizard

#define MyAppName "Secure Manager"
#define MyAppVersion "1.0"
#define MyAppPublisher "Secure Manager Team"
#define MyAppExeName "SecureManager.exe"
#define MyAppURL "https://github.com/yourusername/securemanager"

[Setup]
; Basic app information
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}

; Installation paths - USER CAN CHOOSE
DefaultDirName={autopf}\SecureManager
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
DisableDirPage=no
DisableProgramGroupPage=no

; Output
OutputDir=installer_output
OutputBaseFilename=SecureManager_Setup_v1.0
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
VersionInfoVersion=1.0.0.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Setup
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion=1.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startmenu"; Description: "Create Start Menu shortcut"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce
Name: "quicklaunch"; Description: "Create Quick Launch shortcut"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked; OnlyBelowVersion: 6.1

[Files]
; The main executable
Source: "dist\SecureManager.exe"; DestDir: "{app}"; Flags: ignoreversion
; Documentation
Source: "README.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "INSTALLER_README.txt"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Icons]
; Start Menu shortcuts (if selected)
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: startmenu
Name: "{group}\README"; Filename: "{app}\README.txt"; Tasks: startmenu
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"; Tasks: startmenu

; Desktop shortcut (if selected)
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

; Quick Launch (if selected)
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: quicklaunch

[Run]
; Option to run the app after installation
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Clean up data files on uninstall (optional - ask user first)
Type: filesandordirs; Name: "{app}\my_documents"
Type: files; Name: "{app}\passwords.enc"
Type: files; Name: "{app}\documents.json"
Type: files; Name: "{app}\secret.key"

[Code]
// Custom uninstall confirmation
function InitializeUninstall(): Boolean;
var
  Response: Integer;
begin
  Response := MsgBox('WARNING: This will delete all your saved passwords and documents!' + #13#10 + #13#10 +
                     'Make sure you have backed up your data before continuing.' + #13#10 + #13#10 +
                     'Do you want to continue with uninstallation?',
                     mbConfirmation, MB_YESNO);
  Result := Response = IDYES;
end;
