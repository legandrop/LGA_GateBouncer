@echo off
setlocal
set "QT_ROOT=C:\Qt\6.8.2\mingw_64"
set "MINGW_ROOT=C:\Qt\Tools\mingw1310_64"
set "NINJA_ROOT=C:\Qt\Tools\Ninja"
if not exist "%QT_ROOT%\bin\qt-cmake.bat" (
  echo No se encontro Qt 6.8.2 en QT_ROOT.
  exit /b 2
)
if not exist "%MINGW_ROOT%\bin\g++.exe" (
  echo No se encontro el compilador MinGW 13.1.
  exit /b 2
)
if not exist "%NINJA_ROOT%\ninja.exe" (
  echo No se encontro Ninja.
  exit /b 2
)
if not "%~1"=="" if not "%~1"=="--no-run" (
  echo Uso: compilar.bat --no-run
  exit /b 2
)
set "PATH=%MINGW_ROOT%\bin;%NINJA_ROOT%;%QT_ROOT%\bin;%PATH%"
if not defined GATEBOUNCER_BUILD_DIR set "GATEBOUNCER_BUILD_DIR=%~dp0build"
if defined GATEBOUNCER_OBSERVER_SOURCE (
  call "%QT_ROOT%\bin\qt-cmake.bat" -S "%~dp0." -B "%GATEBOUNCER_BUILD_DIR%" -G Ninja -DCMAKE_BUILD_TYPE=Release -DGATEBOUNCER_OBSERVER_SOURCE="%GATEBOUNCER_OBSERVER_SOURCE%"
) else (
  call "%QT_ROOT%\bin\qt-cmake.bat" -S "%~dp0." -B "%GATEBOUNCER_BUILD_DIR%" -G Ninja -DCMAKE_BUILD_TYPE=Release -DGATEBOUNCER_OBSERVER_SOURCE=
)
if errorlevel 1 exit /b 1
cmake --build "%GATEBOUNCER_BUILD_DIR%" --parallel 4
if errorlevel 1 exit /b 1
echo Compilacion lista. El script no inicia la aplicacion.
exit /b 0