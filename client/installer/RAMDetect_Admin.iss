#define MyAppName "RAMDetect"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "UTHM FYP"
#define MyAppExeName "RAMDetect.exe"

[Setup]
AppId={{RAMDETECT-ADMIN-1.0}}
AppName={#MyAppName} Admin Client
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName=C:\RAMDetect Admin
DefaultGroupName=RAMDetect Admin
OutputDir=..\release
OutputBaseFilename=RAMDetect_Admin_Setup
SetupIconFile=..\assets\ramdetect.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
DisableProgramGroupPage=no
UninstallDisplayIcon={app}\RAMDetect.exe

[Files]
Source: "..\dist\RAMDetect\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\Configure_RAMDetect_Admin_Server.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README_ADMIN_DEPLOYMENT.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\RAMDetect Admin"; Filename: "{app}\RAMDetect.exe"
Name: "{autodesktop}\RAMDetect Admin"; Filename: "{app}\RAMDetect.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Run]
Filename: "{app}\RAMDetect.exe"; Description: "Launch RAMDetect Admin"; Flags: nowait postinstall skipifsilent

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
var
  EnvFile: String;
begin
  if CurStep = ssPostInstall then
  begin
    EnvFile := ExpandConstant('{app}\RAMDetect_ADMIN_ENV_TEMPLATE.txt');
    SaveStringToFile(EnvFile,
      'RAMDetect Admin Client Environment Template' + #13#10 +
      '==============================================' + #13#10 +
      'Run these commands on the admin workstation after installation:' + #13#10 + #13#10 +
      'setx RAMDETECT_RUNTIME_MODE "auto"' + #13#10 +
      'setx RAMDETECT_DB_URL "postgresql+psycopg2://ramdetect_app:changeme@<PTM_SERVER_IP>:5432/ramdetect_db"' + #13#10 +
      'setx RAMDETECT_REPOSITORY_API_URL "http://<PTM_SERVER_IP>:8765"' + #13#10 +
      'setx RAMDETECT_REPOSITORY_API_TOKEN "<CLIENT_UPLOAD_TOKEN>"' + #13#10 +
      'setx RAMDETECT_REPOSITORY_ADMIN_API_TOKEN "<ADMIN_TOKEN>"' + #13#10,
      False);
  end;
end;



