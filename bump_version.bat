@echo off
setlocal
rem Bump de version para publicar un release: sube CMakeLists.txt a la version que encabeza
rem docs\ChangeLog.md y ofrece commitear, pushear y armar el instalador. Lo corre Lega cuando decide
rem publicar, nunca se corre solo. La logica esta en tools\bump_version.ps1; esto es solo el wrapper.
rem Uso: bump_version.bat [--check] [--commit^|--no-commit] [--installer^|--no-installer]
set "FLAGS="
:args
if "%~1"=="" goto run
set "FLAG="
if /I "%~1"=="--check" set "FLAG=-Check"
if /I "%~1"=="--commit" set "FLAG=-Commit"
if /I "%~1"=="--no-commit" set "FLAG=-NoCommit"
if /I "%~1"=="--installer" set "FLAG=-Installer"
if /I "%~1"=="--no-installer" set "FLAG=-NoInstaller"
if not defined FLAG (
    echo [bump_version] ERROR: flag desconocido: %~1
    endlocal & exit /b 2
)
set "FLAGS=%FLAGS% %FLAG%"
shift
goto args
:run
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\bump_version.ps1" %FLAGS%
set "EXIT_CODE=%ERRORLEVEL%"
endlocal & exit /b %EXIT_CODE%
