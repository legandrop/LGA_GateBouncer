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
; Las fuentes van embebidas en GateBouncer.exe; la licencia OFL pide que su texto acompañe la distribución.
Source: "resources\fonts\LICENSE.txt"; DestDir: "{app}\licenses"; DestName: "Inter-LICENSE.txt"; Flags: ignoreversion
Source: "resources\fonts\LICENSE-BricolageGrotesque.txt"; DestDir: "{app}\licenses"; Flags: ignoreversion
Source: "docs\ThirdPartyNotices.md"; DestDir: "{app}\licenses"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"

; Lo que el motor o la ventana dejan en la carpeta (copias .old de una actualización en uso, el script de emergencia
; de una instalación a mano). Las reglas viven en ProgramData y se tratan aparte, abajo.
[UninstallDelete]
Type: files; Name: "{app}\*.old"
Type: files; Name: "{app}\*.new"
Type: files; Name: "{app}\emergencia.ps1"
Type: files; Name: "{app}\generic\*.old"
Type: files; Name: "{app}\iconengines\*.old"
Type: files; Name: "{app}\imageformats\*.old"
Type: files; Name: "{app}\networkinformation\*.old"
Type: files; Name: "{app}\platforms\*.old"
Type: files; Name: "{app}\styles\*.old"
Type: files; Name: "{app}\tls\*.old"
Type: dirifempty; Name: "{app}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[Code]
const
  ServiceName = 'LGAGateBouncer';

var
  // PrepareToInstall detuvo el servicio; PostInstallReached: ya se intentó --install con los archivos nuevos.
  ServiceStopped, PostInstallReached: Boolean;
  // El motor ya quitó el servicio y sus filtros; UninstallStarted: el usuario confirmó y empezó el borrado.
  EngineRemoved, UninstallStarted: Boolean;
  // El servicio corría antes de desinstalar: sólo entonces se restaura si el usuario se arrepiente.
  ServiceWasRunning: Boolean;

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
  ServiceStopped := Exec(ExpandConstant('{sys}\net.exe'), 'stop ' + ServiceName, '', SW_HIDE, ewWaitUntilTerminated,
                         ResultCode) and (ResultCode = 0);
  ExtractTemporaryFile('close_by_path.ps1');
  CloseWindows(ExpandConstant('{tmp}\close_by_path.ps1'));
end;

// Con los archivos nuevos: el motor registra y arranca el servicio (o sólo lo arranca, si ya estaba) y la ventana al
// iniciar sesión. Si falla se avisa: sin servicio, las apps nuevas no pueden pedir permiso.
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep <> ssPostInstall then Exit;
  PostInstallReached := True;
  WizardForm.StatusLabel.Caption := 'Starting the GateBouncer service...';
  if not Exec(ExpandConstant('{app}\{#EngineExeName}'), '--install', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
     or (ResultCode <> 0) then
    MsgBox('The GateBouncer service did not start. Saved rules still apply, but new applications cannot ask for ' +
           'access until it runs. Restart Windows or run the installer again.', mbError, MB_OK);
end;

// Instalación cancelada antes de copiar los archivos nuevos: se vuelve a arrancar el servicio que ya estaba. Si
// --install falló no se fuerza nada: el motor pudo negarse por una razón de seguridad (carpeta no protegida).
procedure DeinitializeSetup();
var
  ResultCode: Integer;
begin
  if ServiceStopped and not PostInstallReached then
    Exec(ExpandConstant('{sys}\net.exe'), 'start ' + ServiceName, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// Antes de borrar nada, el motor quita el servicio, sus filtros y el inicio de la ventana. Si no puede (el servicio
// no se detiene, los filtros no se quitan), la desinstalación no sigue: borrar los archivos dejaría filtros sin nadie
// que los administre y sin el exe para quitarlos.
function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  if not FileExists(ExpandConstant('{app}\{#EngineExeName}')) then Exit;
  ServiceWasRunning := Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
                            '-NoProfile -NonInteractive -Command "if ((Get-Service ' + ServiceName +
                            ' -ErrorAction Stop).Status -eq ''Running'') { exit 0 } else { exit 1 }"',
                            '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
  if not Exec(ExpandConstant('{app}\{#EngineExeName}'), '--uninstall', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
     or (ResultCode <> 0) then begin
    MsgBox('GateBouncer could not remove its service and filters, so nothing was uninstalled.' + #13#10 + 'Run "' +
           ExpandConstant('{app}\{#EngineExeName}') + ' --remove-filters" as administrator to restore network ' +
           'access, then try again.', mbError, MB_OK);
    Result := False;
    Exit;
  end;
  EngineRemoved := True;
end;

// Si después de eso el usuario contesta «No» a la confirmación, nada se borró: si el servicio corría, el motor vuelve a
// instalarse con sus reglas, así que no queda una PC sin firewall por arrepentirse. Si no corría, queda apagado.
procedure DeinitializeUninstall();
var
  ResultCode: Integer;
begin
  if EngineRemoved and ServiceWasRunning and not UninstallStarted then
    if not Exec(ExpandConstant('{app}\{#EngineExeName}'), '--install', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
       or (ResultCode <> 0) then
      MsgBox('GateBouncer was not uninstalled, but its service could not be started again. Saved rules are kept; ' +
             'run the installer again to turn the firewall back on.', mbError, MB_OK);
end;

// Las reglas quedan por defecto (una reinstalación las recupera); se borran sólo si el usuario lo pide.
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then begin
    UninstallStarted := True;
    CloseWindows(ExpandConstant('{app}\tools\close_by_path.ps1'));
  end;
  if (CurUninstallStep = usPostUninstall) and not UninstallSilent and
     (MsgBox('Also delete your saved GateBouncer rules and settings?', mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES) then begin
    DelTree(ExpandConstant('{commonappdata}\LGA GateBouncer'), True, True, True);
    // Datos de la ventana (Qt usa el nombre de la app) y las keys de las explicaciones.
    DelTree(ExpandConstant('{localappdata}\LGA\LGA GateBouncer'), True, True, True);
    DelTree(ExpandConstant('{localappdata}\LGA\GateBouncer'), True, True, True);
    RegDeleteKeyIncludingSubkeys(HKCU, 'Software\LGA\GateBouncer');
    RegDeleteKeyIncludingSubkeys(HKCU, 'Software\LGA\LGA GateBouncer');
  end;
end;
