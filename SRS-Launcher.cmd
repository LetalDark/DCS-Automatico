@echo off
title DCS SimpleRadio Standalone - Launcher
color 0b

echo.
echo ================================================
echo   DCS-SRS Launcher - Actualizar y Ejecutar
echo ================================================
echo.
echo Este launcher necesita acceso a internet para:
echo   - Comprobar si hay una version mas nueva de SRS
echo   - Descargar los archivos personalizados
echo.
echo Si aparece una ventana pidiendo permiso de conexion a internet,
echo pulsa "Permitir" (solo la primera vez).
echo.

set "TARGET_DIR=%LOCALAPPDATA%\DCS-SimpleRadio-Standalone\Client"
set "URL=https://raw.githubusercontent.com/LetalDark/DCS-Automatico/refs/heads/main/SRS-Launcher.ps1"
set "PS1_FILE=%TARGET_DIR%\SRS-Launcher.ps1"

:: Crear carpeta si no existe
if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%" >nul 2>&1

:: Descargar el script principal
powershell -NoProfile -Command "Invoke-WebRequest -Uri '%URL%' -OutFile '%PS1_FILE%' -UseBasicParsing" >nul 2>&1

:: Ejecutar
if exist "%PS1_FILE%" (
    cd /d "%TARGET_DIR%"
    powershell -NoProfile -ExecutionPolicy RemoteSigned -File "SRS-Launcher.ps1"
) else (
    echo.
    echo [ERROR] No se pudo descargar SRS-Launcher.ps1
    pause
)