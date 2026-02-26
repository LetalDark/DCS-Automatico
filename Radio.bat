@echo off
title DCS SimpleRadio Standalone Launcher
color 0b

set "TARGET_DIR=%LOCALAPPDATA%\DCS-SimpleRadio-Standalone\Client"
set "URL=https://raw.githubusercontent.com/LetalDark/DCS-Automatico/refs/heads/main/Start_Radio.ps1"
set "PS1_FILE=%TARGET_DIR%\Start_Radio.ps1"

:: Crear carpeta si no existe
if not exist "%TARGET_DIR%" (
    mkdir "%TARGET_DIR%" >nul 2>&1
)

:: Descargar el script principal
powershell -NoProfile -Command "Invoke-WebRequest -Uri '%URL%' -OutFile '%PS1_FILE%' -UseBasicParsing" >nul 2>&1

:: Ejecutar
if exist "%PS1_FILE%" (
    cd /d "%TARGET_DIR%"
    powershell -NoProfile -ExecutionPolicy RemoteSigned -File "Start_Radio.ps1"
) else (
    echo Error: No se pudo descargar el launcher.
    pause
)
