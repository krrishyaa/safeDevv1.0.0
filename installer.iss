#define MyAppName "SafeDev"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "SafeDev"
#define MyAppExeName "safedev.exe"
#define MyAppBatName "safedev.cmd"

[Setup]
AppId={{8D3D4F3D-6B7C-4A6E-9D48-2F51D1A9F001}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\SafeDev
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=dist
OutputBaseFilename=SafeDev-Installer
Compression=lzma
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64
PrivilegesRequired=admin
ChangesEnvironment=yes
UninstallDisplayIcon={app}\{#MyAppExeName}

[Tasks]
Name: "addtopath"; Description: "Add SafeDev to PATH"; GroupDescription: "Additional tasks:"; Flags: checkedonce

[Files]
Source: "dist\safedev.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "safedev\rules\rules.json"; DestDir: "{app}\safedev\rules"; Flags: ignoreversion
Source: "safedev\ui\dashboard.py"; DestDir: "{app}\safedev\ui"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"

[Run]
Filename: "{cmd}"; Parameters: "/c assoc .safedev=SafeDevFile"; Flags: runhidden
Filename: "{cmd}"; Parameters: "/c ftype SafeDevFile=""{app}\{#MyAppExeName}"" ""%1"""; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Description: "Launch SafeDev"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{cmd}"; Parameters: "/c assoc .safedev="; Flags: runhidden
Filename: "{cmd}"; Parameters: "/c ftype SafeDevFile="; Flags: runhidden

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
var
  PathValue: string;
  Paths: string;
begin
  if CurStep = ssPostInstall then
  begin
    if WizardIsTaskSelected('addtopath') then
    begin
      if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', PathValue) then
        PathValue := '';

      Paths := ';' + Lowercase(PathValue) + ';';
      if Pos(';' + Lowercase(ExpandConstant('{app}')) + ';', Paths) = 0 then
      begin
        if (PathValue <> '') and (Copy(PathValue, Length(PathValue), 1) <> ';') then
          PathValue := PathValue + ';';
        PathValue := PathValue + ExpandConstant('{app}');
        RegWriteStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', PathValue);
      end;
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  PathValue: string;
  AppPath: string;
begin
  if CurUninstallStep = usUninstall then
  begin
    AppPath := ExpandConstant('{app}');
    if RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', PathValue) then
    begin
      if Pos(';' + AppPath + ';', PathValue) > 0 then
        PathValue := Copy(PathValue, 1, Pos(';' + AppPath + ';', PathValue) - 1) + 
                   Copy(PathValue, Pos(';' + AppPath + ';', PathValue) + Length(AppPath) + 1, Length(PathValue))
      else if Pos(AppPath + ';', PathValue) > 0 then
        PathValue := Copy(PathValue, Pos(AppPath + ';', PathValue) + Length(AppPath) + 1, Length(PathValue))
      else if Pos(';' + AppPath, PathValue) > 0 then
        PathValue := Copy(PathValue, 1, Pos(';' + AppPath, PathValue) - 1);
      RegWriteStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', PathValue);
    end;
  end;
end;
