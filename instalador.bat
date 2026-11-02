@echo off
setlocal
rem Arma el instalador local: compila la ventana y el motor, junta los archivos y corre Inno Setup.
rem No publica, no instala ni ejecuta nada.
if not "%~1"=="--no-run" (
  echo Uso: instalador.bat --no-run
  exit /b 2
)
set "ROOT=%~dp0"
set "QT_ROOT=C:\Qt\6.8.2\mingw_64"
set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" (
  echo No se encontro Inno Setup 6.
  exit /b 2
)
if not defined GATEBOUNCER_BUILD_DIR set "GATEBOUNCER_BUILD_DIR=%ROOT%build"
if not defined GATEBOUNCER_ENGINE_BUILD_DIR set "GATEBOUNCER_ENGINE_BUILD_DIR=%ROOT%build-engine"
if not defined GATEBOUNCER_DEPLOY_DIR set "GATEBOUNCER_DEPLOY_DIR=%ROOT%deploy"
if not defined GATEBOUNCER_INSTALLER_DIR set "GATEBOUNCER_INSTALLER_DIR=%ROOT%installer"

call "%ROOT%compilar.bat" --no-run
if errorlevel 1 exit /b 1
call "%ROOT%engine\compilar.bat" --no-run
if errorlevel 1 exit /b 1

rem La carpeta de archivos se rehace entera para no arrastrar restos de otra version. Solo se borra si la creo este
rem script (lleva su marca): una variable mal puesta nunca borra otra carpeta.
if exist "%GATEBOUNCER_DEPLOY_DIR%\" (
  if not exist "%GATEBOUNCER_DEPLOY_DIR%\.gatebouncer-deploy" (
    echo %GATEBOUNCER_DEPLOY_DIR% existe y no es una carpeta de este script. No se toca.
    exit /b 1
  )
  rmdir /s /q "%GATEBOUNCER_DEPLOY_DIR%"
)
mkdir "%GATEBOUNCER_DEPLOY_DIR%" || exit /b 1
type nul > "%GATEBOUNCER_DEPLOY_DIR%\.gatebouncer-deploy"
copy /y "%GATEBOUNCER_BUILD_DIR%\GateBouncer.exe" "%GATEBOUNCER_DEPLOY_DIR%\" >nul || exit /b 1
copy /y "%GATEBOUNCER_ENGINE_BUILD_DIR%\GateBouncerEngine.exe" "%GATEBOUNCER_DEPLOY_DIR%\" >nul || exit /b 1
set "PATH=C:\Qt\Tools\mingw1310_64\bin;%QT_ROOT%\bin;%PATH%"
"%QT_ROOT%\bin\windeployqt.exe" --release --no-translations --no-system-d3d-compiler --no-opengl-sw --no-compiler-runtime "%GATEBOUNCER_DEPLOY_DIR%\GateBouncer.exe"
if errorlevel 1 exit /b 1
rem Runtime de MinGW: windeployqt no lo copia con --no-compiler-runtime, se toma del compilador usado.
for %%D in (libgcc_s_seh-1.dll libstdc++-6.dll libwinpthread-1.dll) do (
  copy /y "C:\Qt\Tools\mingw1310_64\bin\%%D" "%GATEBOUNCER_DEPLOY_DIR%\" >nul || exit /b 1
)
"%ISCC%" /Q /DSourceDir="%GATEBOUNCER_DEPLOY_DIR%" /O"%GATEBOUNCER_INSTALLER_DIR%" "%ROOT%GateBouncer_installer.iss"
if errorlevel 1 exit /b 1
echo Instalador listo en %GATEBOUNCER_INSTALLER_DIR%. No se ejecuto nada.
exit /b 0
