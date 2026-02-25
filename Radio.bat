@echo off
title SRS Launcher
color 0b

set "TARGET_DIR=C:\Program Files\DCS-SimpleRadio-Standalone\Client"
set "URL=https://raw.githubusercontent.com/LetalDark/DCS-Automatico/refs/heads/main/Start_Radio.ps1"
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
    if exist "%TARGET_DIR%" (
        echo [OK] Carpeta creada correctamente.
    ) else (
        echo [ERROR] No se pudo crear la carpeta.
        pause
        exit /b 1
    )
) else (
    echo [INFO] Carpeta Client ya existe.
)

:: === Descargar Start_Radio.ps1 (con elevacion si hace falta) ===
echo.
echo [SRS] Descargando la ultima version...

:: Primero intentamos sin admin
powershell -Command "$progressPreference = 'silentlyContinue'; try { iwr -Uri '%URL%' -OutFile '%PS1_FILE%' -UseBasicParsing; Write-Host '[OK] Actualizado' -ForegroundColor Green; exit 0 } catch { exit 1 }" >nul 2>&1

if errorlevel 1 (
    echo [INFO] Se necesitan permisos de administrador para actualizar...
    echo $url = '%URL%' > "%TEMP%\DownloadSRS.ps1"
    echo $out = '%PS1_FILE%' >> "%TEMP%\DownloadSRS.ps1"
    echo try { iwr -Uri $url -OutFile $out -UseBasicParsing; Write-Host '[OK] Actualizado correctamente' -ForegroundColor Green } catch { Write-Host '[ERROR] Fallo incluso con admin:' -ForegroundColor Red; $_.Exception.Message } >> "%TEMP%\DownloadSRS.ps1"
    echo exit >> "%TEMP%\DownloadSRS.ps1"
    
    powershell -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%TEMP%\DownloadSRS.ps1\"' -Wait"
)

:: === Ejecutar ===
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

echo.
echo ================================================
echo Todo correcto.
exit
