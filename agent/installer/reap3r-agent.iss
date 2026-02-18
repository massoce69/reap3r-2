; ─────────────────────────────────────────────────────────────────────────────
; MASSVISION Reap3r Agent — Inno Setup Installer Script
; Build: "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" reap3r-agent.iss
; ─────────────────────────────────────────────────────────────────────────────

#define AppName      "Reap3r Agent"
#define AppVersion   "1.0.0"
#define AppPublisher "MASSVISION"
#define AppURL       "https://massvision.io"
#define ExeName      "reap3r-agent.exe"
#define ServiceName  "Reap3rAgent"
#define ServiceDisp  "Reap3r Agent (MASSVISION)"

[Setup]
AppId={{B2F1D3E4-7A5C-4F8B-9D2E-1A3C5B7D9F0E}}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={autopf}\Reap3r Agent
DefaultGroupName={#AppName}
AllowNoIcons=yes
OutputDir=..\dist
OutputBaseFilename=Reap3rAgentSetup-{#AppVersion}
SetupIconFile=..\assets\icon.ico
; If no icon file, comment above and uncomment:
; SetupIconFile=
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
WindowVisible=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#ExeName}
CloseApplications=yes

; Custom wizard pages for server + token input
[Code]
var
  ServerPage: TInputQueryWizardPage;
  TokenPage:  TInputQueryWizardPage;

procedure InitializeWizard;
begin
  ServerPage := CreateInputQueryPage(wpWelcome,
    'Server Connection',
    'Enter your Reap3r backend WebSocket URL.',
    '');
  ServerPage.Add('Server URL (e.g. wss://reap3r.example.com/ws/agent):', False);
  ServerPage.Values[0] := ExpandConstant('{param:SERVER|wss://YOUR_SERVER/ws/agent}');

  TokenPage := CreateInputQueryPage(ServerPage.ID,
    'Enrollment Token',
    'Enter the one-time enrollment token provided by your administrator.',
    '');
  TokenPage.Add('Enrollment Token:', False);
  TokenPage.Values[0] := ExpandConstant('{param:TOKEN|}');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = ServerPage.ID then begin
    if ServerPage.Values[0] = '' then begin
      MsgBox('Please enter a valid server URL.', mbError, MB_OK);
      Result := False;
    end else if (Pos('ws://', ServerPage.Values[0]) = 0) and
                (Pos('wss://', ServerPage.Values[0]) = 0) then begin
      MsgBox('Server URL must start with ws:// or wss://', mbError, MB_OK);
      Result := False;
    end;
  end;
  if CurPageID = TokenPage.ID then begin
    if TokenPage.Values[0] = '' then begin
      MsgBox('Please enter an enrollment token.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Main binary (built with: cargo build --release --target x86_64-pc-windows-msvc)
Source: "..\target\x86_64-pc-windows-msvc\release\{#ExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName} — Diagnose"; Filename: "{app}\{#ExeName}"; Parameters: "--diagnose"; WorkingDir: "{app}"
Name: "{group}\{#AppName} — Open Log"; Filename: "{win}\explorer.exe"; Parameters: "{commonappdata}\Reap3r\logs"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{commondesktop}\{#AppName}"; Filename: "{app}\{#ExeName}"; Parameters: "--diagnose"; Tasks: desktopicon

[Dirs]
Name: "{commonappdata}\Reap3r"
Name: "{commonappdata}\Reap3r\logs"

[Run]
; Stop existing service before install
Filename: "{sys}\sc.exe"; Parameters: "stop {#ServiceName}"; Flags: runhidden waituntilterminated; StatusMsg: "Stopping existing service..."
Filename: "{sys}\sc.exe"; Parameters: "delete {#ServiceName}"; Flags: runhidden waituntilterminated; StatusMsg: "Removing old service..."

; Install new service
Filename: "{sys}\sc.exe"; \
  Parameters: "create {#ServiceName} binPath= ""{app}\{#ExeName} --server ""{code:GetServer}"" --token ""{code:GetToken}"""" start= auto DisplayName= ""{#ServiceDisp}"""; \
  Flags: runhidden waituntilterminated; \
  StatusMsg: "Installing Windows service..."

; Set service description
Filename: "{sys}\sc.exe"; Parameters: "description {#ServiceName} ""MASSVISION Reap3r remote-management agent"""; Flags: runhidden waituntilterminated

; Configure recovery: restart on failure (3 restarts in 86400s window)
Filename: "{sys}\sc.exe"; \
  Parameters: "failure {#ServiceName} reset= 86400 actions= restart/5000/restart/10000/restart/30000"; \
  Flags: runhidden waituntilterminated

; Start the service
Filename: "{sys}\net.exe"; Parameters: "start {#ServiceName}"; Flags: runhidden waituntilterminated; StatusMsg: "Starting Reap3r Agent service..."

; Launch diagnose in a visible window so user can see output
Filename: "{app}\{#ExeName}"; Parameters: "--diagnose"; Description: "Run diagnostics after install"; Flags: postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\net.exe"; Parameters: "stop {#ServiceName}"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "delete {#ServiceName}"; Flags: runhidden waituntilterminated

[Code]
function GetServer(Param: String): String;
begin
  Result := ServerPage.Values[0];
end;

function GetToken(Param: String): String;
begin
  Result := TokenPage.Values[0];
end;
