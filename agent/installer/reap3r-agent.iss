; ════════════════════════════════════════════════════════════════════════════════
; MASSVISION Reap3r Agent — Inno Setup Installer (Universal)
;
; Compatible: Windows 7 SP1 → Windows Server 2025 (x86 + x64)
; Build:      "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" reap3r-agent.iss
;
; Silent install (GPO/Intune/Zabbix/SCCM):
;   reap3r-agent-setup.exe /VERYSILENT /SERVER=wss://your-server/ws/agent /TOKEN=abc123
;
; Unattended uninstall:
;   "C:\Program Files\MASSVISION\Reap3r Agent\unins000.exe" /VERYSILENT
; ════════════════════════════════════════════════════════════════════════════════

#define AppName      "MASSVISION Reap3r Agent"
#define AppVersion   "1.2.0"
#define AppPublisher "MASSVISION"
#define AppURL       "https://massvision.io"
#define ExeName      "reap3r-agent.exe"
#define ServiceName  "MASSVISION-Reap3r-Agent"
#define ServiceDisp  "MASSVISION Reap3r Agent"

[Setup]
AppId={{B2F1D3E4-7A5C-4F8B-9D2E-1A3C5B7D9F0E}}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={autopf}\MASSVISION\Reap3r Agent
DefaultGroupName={#AppName}
AllowNoIcons=yes
OutputDir=..\dist
OutputBaseFilename=reap3r-agent-setup-{#AppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
WizardStyle=modern
UninstallDisplayIcon={app}\{#ExeName}
CloseApplications=yes
; Minimum: Windows 7 SP1 (NT 6.1 SP1)
MinVersion=6.1sp1
; Auto-detect 64-bit and install in Program Files (not x86)
ArchitecturesInstallIn64BitMode=x64compatible
; Disable the "ready to install" page for faster installs
DisableReadyPage=yes
; Version info for the setup executable itself
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription=MASSVISION Reap3r Agent Installer
VersionInfoProductName={#AppName}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "french"; MessagesFile: "compiler:Languages\French.isl"

[Files]
; Architecture-aware: install the correct binary automatically
Source: "..\dist\reap3r-agent-x64.exe"; DestDir: "{app}"; DestName: "{#ExeName}"; Check: Is64BitInstallMode; Flags: ignoreversion
Source: "..\dist\reap3r-agent-x86.exe"; DestDir: "{app}"; DestName: "{#ExeName}"; Check: not Is64BitInstallMode; Flags: ignoreversion

[Dirs]
Name: "{commonappdata}\Reap3r"; Permissions: admins-full system-full
Name: "{commonappdata}\Reap3r\logs"; Permissions: admins-full system-full

[Icons]
Name: "{group}\{#AppName} — Diagnostics"; Filename: "{app}\{#ExeName}"; Parameters: "--diagnose"; WorkingDir: "{app}"
Name: "{group}\{#AppName} — View Logs"; Filename: "notepad.exe"; Parameters: "{commonappdata}\Reap3r\logs\agent.log"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"

[Run]
; Pre-install: stop & remove any existing service (upgrade scenario)
Filename: "{sys}\sc.exe"; Parameters: "stop {#ServiceName}"; Flags: runhidden waituntilterminated; StatusMsg: "Stopping existing service..."; Check: ServiceExists
Filename: "{sys}\sc.exe"; Parameters: "delete {#ServiceName}"; Flags: runhidden waituntilterminated; StatusMsg: "Removing old service..."; Check: ServiceExists

; Install service using the agent's built-in --install (handles bootstrap, recovery, event log)
Filename: "{app}\{#ExeName}"; Parameters: "--install {code:GetInstallArgs}"; Flags: runhidden waituntilterminated; StatusMsg: "Installing Windows Service..."

; Post-install: run diagnostics (interactive only)
Filename: "{app}\{#ExeName}"; Parameters: "--diagnose"; Description: "Run agent diagnostics"; Flags: postinstall skipifsilent nowait

[UninstallRun]
; Uninstall: stop service, remove service, clean event log
Filename: "{app}\{#ExeName}"; Parameters: "--uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "UninstallService"

[Code]
var
  ServerPage: TInputQueryWizardPage;
  TokenPage: TInputQueryWizardPage;

// Parse /PARAM=value from command line (for silent installs via GPO etc.)
function GetCmdLineParam(const ParamName: string): string;
var
  I: Integer;
  S, Prefix: string;
begin
  Result := '';
  Prefix := '/' + UpperCase(ParamName) + '=';
  for I := 1 to ParamCount do
  begin
    S := ParamStr(I);
    if Pos(Prefix, UpperCase(S)) = 1 then
    begin
      Result := Copy(S, Length(Prefix) + 1, MaxInt);
      Exit;
    end;
  end;
end;

function ServiceExists: Boolean;
var
  Res: Integer;
begin
  // Check if service is registered
  Exec(ExpandConstant('{sys}\sc.exe'), ExpandConstant('query {#ServiceName}'), '', SW_HIDE, ewWaitUntilTerminated, Res);
  Result := (Res = 0);
end;

procedure InitializeWizard;
begin
  // Server URL page
  ServerPage := CreateInputQueryPage(wpSelectDir,
    'Server Connection',
    'Enter your MASSVISION backend WebSocket URL.',
    'The agent needs to know the server address to connect.' + #13#10 +
    'Example: wss://reap3r.yourcompany.com/ws/agent');
  ServerPage.Add('Server URL:', False);
  ServerPage.Values[0] := GetCmdLineParam('SERVER');
  if ServerPage.Values[0] = '' then
    ServerPage.Values[0] := 'wss://';

  // Enrollment token page
  TokenPage := CreateInputQueryPage(ServerPage.ID,
    'Enrollment Token',
    'Enter the enrollment token for this agent.',
    'This token is used for the initial enrollment with the management server.' + #13#10 +
    'Your administrator can generate tokens from the admin panel.');
  TokenPage.Add('Enrollment Token:', False);
  TokenPage.Values[0] := GetCmdLineParam('TOKEN');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = ServerPage.ID then
  begin
    if (ServerPage.Values[0] = '') or (ServerPage.Values[0] = 'wss://') then
    begin
      MsgBox('Please enter a valid server WebSocket URL.' + #13#10 +
             'Example: wss://reap3r.yourcompany.com/ws/agent', mbError, MB_OK);
      Result := False;
    end
    else if (Pos('ws://', ServerPage.Values[0]) <> 1) and
            (Pos('wss://', ServerPage.Values[0]) <> 1) then
    begin
      MsgBox('Server URL must start with ws:// or wss://', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function GetInstallArgs(Param: string): string;
var
  Server, Token: string;
begin
  // Priority: command-line params (for silent) > wizard pages (for GUI)
  Server := GetCmdLineParam('SERVER');
  Token := GetCmdLineParam('TOKEN');

  if Server = '' then
    Server := ServerPage.Values[0];
  if Token = '' then
    Token := TokenPage.Values[0];

  Result := '';
  if (Server <> '') and (Server <> 'wss://') then
    Result := Result + ' --server "' + Server + '"';
  if Token <> '' then
    Result := Result + ' --token "' + Token + '"';
end;