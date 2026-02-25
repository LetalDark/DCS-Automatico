@echo off
title SRS Launcher
color 0b

set "TARGET_DIR=C:\Program Files\DCS-SimpleRadio-Standalone\Client"
set "URL=https://github.com/LetalDark/DCS-Automatico/raw/refs/heads/main/Start_Radio.ps1"
set "PS1_FILE=%TARGET_DIR%\Start_Radio.ps1"

echo.
echo ================================================
echo     SRS - Actualizar y Ejecutar
echo ================================================
echo.

:: === Crear carpeta si no existe ===
if not exist "%TARGET_DIR%" (
    echo [INFO] Creando carpeta Client...
    
    echo New-Item -Path "%TARGET_DIR%" -ItemType Directory -Force > "%TEMP%\CreateSRSFolder.ps1"
    echo exit >> "%TEMP%\CreateSRSFolder.ps1"
    
    powershell -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%TEMP%\CreateSRSFolder.ps1\"' -Wait"
    
    timeout /t 2 /nobreak >nul
    
    if not exist "%TARGET_DIR%" (
        echo [ERROR] No se pudo crear la carpeta.
        pause
        exit /b 1
    )
    echo [OK] Carpeta creada correctamente.
) else (
    echo [INFO] Carpeta Client ya existe.
)

:: === Actualizar el script .ps1 ===
echo.
echo [SRS] Descargando la ultima version...
powershell -Command "$progressPreference = 'silentlyContinue'; try { iwr -Uri '%URL%' -OutFile '%PS1_FILE%' -UseBasicParsing; Write-Host '[OK] Actualizado correctamente' -ForegroundColor Green } catch { Write-Host '[ERROR] No se pudo descargar. Usando version local si existe.' -ForegroundColor Red }"

:: === Ejecutar el script .ps1 ===
if exist "%PS1_FILE%" (
    echo.
    echo [SRS] Ejecutando Start_Radio.ps1...
    cd /d "%TARGET_DIR%"
    powershell -ExecutionPolicy Bypass -File "Start_Radio.ps1"
) else (
    echo.
    echo [ERROR] No se encontro Start_Radio.ps1
    pause
    exit /b 1
)

:: === Todo correcto → cerrar automáticamente (sin pausa) ===
echo.
echo ================================================
echo Todo correcto. Cerrando...
exit