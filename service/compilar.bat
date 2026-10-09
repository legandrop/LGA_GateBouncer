@echo off
setlocal
if not "%~1"=="--no-run" (
  echo Uso: compilar.bat --no-run
  exit /b 2
)
if not defined GATEBOUNCER_SERVICE_BUILD_DIR (
  echo Defina GATEBOUNCER_SERVICE_BUILD_DIR con una carpeta de build exclusiva.
  exit /b 2
)
if not exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" exit /b 2
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b 1
"C:\Program Files\CMake\bin\cmake.exe" -S "%~dp0." -B "%GATEBOUNCER_SERVICE_BUILD_DIR%" -G Ninja -DCMAKE_MAKE_PROGRAM="C:/Qt/Tools/Ninja/ninja.exe" -DCMAKE_BUILD_TYPE=Release -DGATEBOUNCER_OFFLINE_TEST_SOURCE="%GATEBOUNCER_OFFLINE_TEST_SOURCE%" -DGATEBOUNCER_DECISIONS_TEST_SOURCE="%GATEBOUNCER_DECISIONS_TEST_SOURCE%"
if errorlevel 1 exit /b 1
"C:\Program Files\CMake\bin\cmake.exe" --build "%GATEBOUNCER_SERVICE_BUILD_DIR%" --parallel 4
if errorlevel 1 exit /b 1
echo Build terminado. No se inicia servicio, ejecutable ni filtro.
exit /b 0
