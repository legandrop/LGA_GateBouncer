@echo off
setlocal
if not "%~1"=="--no-run" (
  echo Uso: compilar.bat --no-run
  exit /b 2
)
if not defined GATEBOUNCER_LOCALFACTS_BUILD_DIR (
  echo Defina GATEBOUNCER_LOCALFACTS_BUILD_DIR con una carpeta de build exclusiva.
  exit /b 2
)
"C:\Program Files\CMake\bin\cmake.exe" -S "%~dp0." -B "%GATEBOUNCER_LOCALFACTS_BUILD_DIR%" -G "Visual Studio 17 2022" -A x64
if errorlevel 1 exit /b 1
"C:\Program Files\CMake\bin\cmake.exe" --build "%GATEBOUNCER_LOCALFACTS_BUILD_DIR%" --config Release
if errorlevel 1 exit /b 1
echo Build terminado. No se inicia ningun ejecutable.
exit /b 0
