; GateBouncer_installer.iss -- fuente escrita a mano. instalador.bat la compila con /DSourceDir (la carpeta con los
; archivos a instalar) y, si hace falta, /DMyAppVersion.
;
; El instalador sólo copia archivos: el servicio, los filtros y el inicio de la ventana los maneja el propio motor
; (--install / --uninstall), igual que una instalación a mano. Las reglas guardadas no se tocan al actualizar.

#define MyAppName "LGA GateBouncer"
#ifndef MyAppVersion
; Sin versión de producto todavía.
#define MyAppVersion "0.1"
#endif
#define MyAppPublisher "LGA"
#define MyAppExeName "GateBouncer.exe"
#define EngineExeName "GateBouncerEngine.exe"
#ifndef SourceDir
#define SourceDir "deploy"
#endif

[Setup]
AppId={{6B1F3C52-8E0A-4D7B-9C3E-2A5F1D9B7E41}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
; El servicio corre como SYSTEM y confía en la ventana de su carpeta: tiene que ser una que sólo los administradores
; pueden cambiar. Por eso la carpeta es fija.
DefaultDirName={autopf}\LGA GateBouncer
DisableDirPage=yes
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputBaseFilename=LGA_GateBouncer_Setup_v{#MyAppVersion}
SetupIconFile=resources\icons\LGA_GateBouncer.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=no

[Files]
Source: "{#SourceDir}\*"; Excludes: ".gatebouncer-deploy"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Script de cierre por ruta (copia de LGA_Base_QT_C_Py): `dontcopy` para PrepareToInstall y en {app}\tools para el
; desinstalador.
Source: "tools\close_by_path.ps1"; Flags: dontcopy
Source: "tools\close_by_path.ps1"; DestDir: "{app}\tools"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"

[Run]
; Registra y arranca el servicio, y la ventana al iniciar sesión. Con el servicio ya registrado sólo lo arranca.
Filename: "{app}\{#EngineExeName}"; Parameters: "--install"; StatusMsg: "Starting the GateBouncer service..."; Flags: runhidden waituntilterminated
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[Code]
const
  ServiceName = 'LGAGateBouncer';

procedure CloseWindows(const ScriptPath: String);
var
  ResultCode: Integer;
begin
  // Sólo las ventanas que corren desde la carpeta instalada, por ruta real (nunca por nombre).
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
              '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ' + #34 + ScriptPath + #34 +
              ' -ExeName {#MyAppExeName} -Prefix ' + #34 + ExpandConstant('{app}') + #34,
              '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Log('close_by_path no se pudo ejecutar');
  Sleep(1000);
end;

// Antes de copiar: el servicio se detiene (los filtros persistentes siguen bloqueando lo desconocido mientras tanto)
// y se cierran las ventanas, para que ningún archivo quede en uso. --install lo vuelve a arrancar.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  Exec(ExpandConstant('{sys}\net.exe'), 'stop ' + ServiceName, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  ExtractTemporaryFile('close_by_path.ps1');
  CloseWindows(ExpandConstant('{tmp}\close_by_path.ps1'));
end;

// Antes de borrar nada: el motor quita el servicio, sus filtros y el inicio de la ventana. Si no puede (el servicio
// no se detiene), la desinstalación no sigue: borrar los archivos dejaría filtros sin nadie que los administre.
function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  if not FileExists(ExpandConstant('{app}\{#EngineExeName}')) then Exit;
  if not Exec(ExpandConstant('{app}\{#EngineExeName}'), '--uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
     or (ResultCode <> 0) then begin
    MsgBox('GateBouncer could not remove its service and filters, so nothing was uninstalled.' + #13#10 +
           'Run "' + ExpandConstant('{app}\{#EngineExeName}') + ' --remove-filters" as administrator to restore ' +
           'network access, then try again.', mbError, MB_OK);
    Result := False;
    Exit;
  end;
  CloseWindows(ExpandConstant('{app}\tools\close_by_path.ps1'));
end;

// Las reglas quedan por defecto (una reinstalación las recupera); se borran sólo si el usuario lo pide.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usPostUninstall) and not UninstallSilent and
     (MsgBox('Also delete your saved GateBouncer rules and settings?', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES) then begin
    DelTree(ExpandConstant('{commonappdata}\LGA GateBouncer'), True, True, True);
    DelTree(ExpandConstant('{localappdata}\LGA\GateBouncer'), True, True, True);
    RegDeleteKeyIncludingSubkeys(HKCU, 'Software\LGA\GateBouncer');
  end;
end;
