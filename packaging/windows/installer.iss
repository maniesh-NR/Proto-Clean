; Inno Setup script for Proto Clean (Windows 10+ x64 modern build).
; Build inside packaging/windows/ after the PyInstaller onedir exists in
; dist/ProtoClean:
;   iscc installer.iss
#define AppName "Proto Clean"
#define AppVersion "0.6.0"
#define AppPublisher "Proto Clean contributors"
#define AppExeName "ProtoClean.exe"
#define AppId "{{8E1F4C77-6D2A-4E8B-9A63-2F1D5B9E4A31}"

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\Proto Clean
DefaultGroupName=Proto Clean
UninstallDisplayIcon={app}\{#AppExeName}
OutputDir=..\..\dist
OutputBaseFilename=Proto-Clean-{#AppVersion}-win-x64-setup
SetupIconFile=proto-clean.ico
Compression=lzma2/max
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
WizardStyle=modern

[Files]
Source: "..\..\dist\ProtoClean\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{group}\Proto Clean"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\Proto Clean"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Shortcuts:"

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Launch Proto Clean"; Flags: nowait postinstall skipifsilent
