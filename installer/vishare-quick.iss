#define AppName "ViShare Quick"
#ifndef AppVersion
  #define AppVersion "alpha_0.8"
#endif
#ifndef VersionInfoVersion
  #define VersionInfoVersion "0.8.0.0"
#endif
#ifndef SourceExe
  #define SourceExe "..\dist\vishare-quick.exe"
#endif

[Setup]
AppId={{7F300B3C-9F20-4A9B-AAEB-7ECBD25B49EA}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=ViShare Quick contributors
AppPublisherURL=https://github.com/ahamviraj/ViShare_Quick
AppSupportURL=https://github.com/ahamviraj/ViShare_Quick/issues
AppUpdatesURL=https://github.com/ahamviraj/ViShare_Quick/releases
DefaultDirName={localappdata}\Programs\ViShare Quick
DefaultGroupName=ViShare Quick
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=output
OutputBaseFilename=ViShare-Quick-Setup-{#AppVersion}
SetupIconFile=vishare-quick.ico
UninstallDisplayIcon={app}\vishare-quick.exe
UninstallDisplayName={#AppName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
VersionInfoVersion={#VersionInfoVersion}
VersionInfoDescription={#AppName} installer
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#VersionInfoVersion}
VersionInfoCompany=ViShare Quick contributors
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked

[Files]
Source: "{#SourceExe}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\vishare-quick.exe"; WorkingDir: "{app}"; Comment: "Local file transfer for Quick Share"; AppUserModelID: "ViShareQuick"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\vishare-quick.exe"; WorkingDir: "{app}"; Comment: "Local file transfer for Quick Share"; AppUserModelID: "ViShareQuick"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\App Paths\vishare-quick.exe"; ValueType: string; ValueName: ""; ValueData: "{app}\vishare-quick.exe"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\App Paths\vishare-quick.exe"; ValueType: string; ValueName: "Path"; ValueData: "{app}"; Flags: uninsdeletekey

[Run]
Filename: "{app}\vishare-quick.exe"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent
