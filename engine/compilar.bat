@echo off
setlocal
rem Compila el motor sin driver con MSVC. Nunca ejecuta nada ni toca el firewall.
if not "%~1"=="--no-run" (
  echo Uso: compilar.bat --no-run
  exit /b 2
)
if not defined GATEBOUNCER_ENGINE_BUILD_DIR set "GATEBOUNCER_ENGINE_BUILD_DIR=%~dp0..\build-engine"
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
  echo No se encontro vcvars64.bat de Visual Studio 2022.
  exit /b 2
)
call "%VCVARS%" >nul
if errorlevel 1 exit /b 1
"C:\Program Files\CMake\bin\cmake.exe" -S "%~dp0." -B "%GATEBOUNCER_ENGINE_BUILD_DIR%" -G Ninja -DCMAKE_MAKE_PROGRAM="C:/Qt/Tools/Ninja/ninja.exe" -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 exit /b 1
"C:\Program Files\CMake\bin\cmake.exe" --build "%GATEBOUNCER_ENGINE_BUILD_DIR%"
if errorlevel 1 exit /b 1
echo Build del motor terminado. No se ejecuta nada.
exit /b 0
