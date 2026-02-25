param([switch]$Elevated, [string]$ZipPath = "")

# === FUNCION: Auto-actualizar Radio.bat ===
function Update-RadioBat {
    $BatUrl  = "https://github.com/LetalDark/DCS-Automatico/raw/refs/heads/main/Radio.bat"
    $BatPath = Join-Path (Split-Path $PSCommandPath -Parent) "Radio.bat"

    Write-Host "[AUTO-UPDATE] Comprobando Radio.bat..." -ForegroundColor Cyan

    try {
        $tempFile = Join-Path $env:TEMP "Radio.bat.new"
        Invoke-WebRequest -Uri $BatUrl -OutFile $tempFile -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop

        if ((Get-Content $tempFile -Raw) -ne (Get-Content $BatPath -Raw -ErrorAction SilentlyContinue)) {
            Copy-Item $tempFile $BatPath -Force
            Write-Host "[OK] Radio.bat actualizado correctamente" -ForegroundColor Green
        } else {
            Write-Host "[OK] Radio.bat esta actualizado" -ForegroundColor Gray
        }
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "[INFO] No se pudo actualizar Radio.bat" -ForegroundColor Yellow
    }
}

# Actualizar el launcher antes de continuar
Update-RadioBat

# === FIX CONEXION SEGURA ===
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# === FUNCION AUXILIAR: Cerrar procesos SRS ===
function Stop-SRSProcesses {
    $processes = @("SR-ClientRadio", "SRS-Server")
    $allStopped = $true

    foreach ($procName in $processes) {
        $running = Get-Process -Name $procName -ErrorAction SilentlyContinue
        if ($running) {
            Write-Host "Detectado proceso $procName.exe en ejecucion..." -ForegroundColor Yellow
            try {
                $running | Stop-Process -Force -ErrorAction Stop
                Start-Sleep -Seconds 1.5
                Write-Host "  -> $procName.exe cerrado correctamente" -ForegroundColor Green
            } catch {
                Write-Host "  -> No se pudo cerrar $procName.exe automaticamente" -ForegroundColor Red
                $allStopped = $false
            }
        }
    }

    return $allStopped
}

# === FUNCION: Detectar si SR-ClientRadio esta abierto (solo detecta) ===
function Test-SRSClientRunning {
    $proc = Get-Process -Name "SR-ClientRadio" -ErrorAction SilentlyContinue
    if ($proc) {
        return $true
    }
    return $false
}

# === FUNCION 1: Comprobar SRS instalado ===
function Get-SRSInstalled {
    $path = "C:\Program Files\DCS-SimpleRadio-Standalone\Client\SR-ClientRadio.exe"
    if (Test-Path $path) {
        $version = (Get-Item $path).VersionInfo.ProductVersion
        return @{ Installed = $true; Version = $version; Path = $path }
    } else {
        return @{ Installed = $false; Version = $null; Path = $null }
    }
}

# === FUNCION 2: Obtener ultima version ===
function Get-SRSLatestVersion {
    try {
        $response = Invoke-WebRequest -Uri "https://github.com/ciribob/DCS-SimpleRadioStandalone/releases/latest" -UseBasicParsing
        $version = $response.BaseResponse.ResponseUri.AbsoluteUri.Split('/')[-1].TrimStart('v')
        return @{ Success = $true; Version = $version }
    } catch {
        Write-Warning "No se pudo obtener la version de GitHub"
        return @{ Success = $false; Version = $null }
    }
}

# === FUNCION 3: Obtener ultimo enlace de descarga ===
function Get-SRSLatestDownloadUrl {
    try {
        $response = Invoke-WebRequest -Uri "https://github.com/ciribob/DCS-SimpleRadioStandalone/releases/latest" -UseBasicParsing
        $version = $response.BaseResponse.ResponseUri.AbsoluteUri.Split('/')[-1].TrimStart('v')
        $downloadUrl = "https://github.com/ciribob/DCS-SimpleRadioStandalone/releases/download/$version/DCS-SimpleRadioStandalone-$version.zip"
        return @{ Success = $true; Version = $version; DownloadUrl = $downloadUrl }
    } catch {
        Write-Warning "No se pudo obtener el enlace de GitHub"
        return @{ Success = $false; Version = $null; DownloadUrl = $null }
    }
}

# === FUNCION 4: Descargar ZIP ===
function Download-SRSLatestZip {
    param([string]$DownloadUrl)
    $destinationFolder = "C:\Temp"
    $fileName = [System.IO.Path]::GetFileName($DownloadUrl)
    $destinationPath = Join-Path $destinationFolder $fileName
    $minSizeBytes = 265MB

    try {
        if (-not (Test-Path $destinationFolder)) { New-Item -Path $destinationFolder -ItemType Directory -Force | Out-Null }

        if (Test-Path $destinationPath) {
            $size = (Get-Item $destinationPath).Length
            if ($size -lt $minSizeBytes) {
                Write-Host "ZIP encontrado pero corrupto ($([math]::Round($size/1MB,1)) MB). Se borra y se vuelve a descargar." -ForegroundColor Yellow
                Remove-Item $destinationPath -Force
            } else {
                Write-Host "El ZIP ya existe y parece correcto ($([math]::Round($size/1MB,1)) MB). Se omite la descarga." -ForegroundColor Cyan
                return @{ Success = $true; FilePath = $destinationPath }
            }
        }

        Write-Host "Descargando SRS ZIP..." 
        Write-Host "Destino: $destinationPath"
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $destinationPath -UseBasicParsing

        $size = (Get-Item $destinationPath).Length
        if ($size -lt $minSizeBytes) {
            Write-Host "Descarga terminada pero parece corrupto ($([math]::Round($size/1MB,1)) MB)" -ForegroundColor Red
            Remove-Item $destinationPath -Force -ErrorAction SilentlyContinue
            return @{ Success = $false; FilePath = $null }
        }

        Write-Host "Descarga completada correctamente! ($([math]::Round($size/1MB,1)) MB)" -ForegroundColor Green
        return @{ Success = $true; FilePath = $destinationPath }
    } catch {
        Write-Host "Error al descargar: $_" -ForegroundColor Red
        return @{ Success = $false; FilePath = $null }
    }
}

# === FUNCION Test-Admin ===
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# === FUNCION 5: Extraer ZIP (robusta con cierre de procesos) ===
function Expand-SRSZip {
    param([string]$ZipPath, [string]$Destination = "C:\Program Files\DCS-SimpleRadio-Standalone")
    try {
        if (-not (Test-Path $ZipPath)) { 
            Write-Host "Error: ZIP no encontrado" -ForegroundColor Red
            return @{ Success = $false } 
        }
        if (-not (Test-Path $Destination)) { 
            New-Item -Path $Destination -ItemType Directory -Force | Out-Null 
        }

        Write-Host "Comprobando procesos SRS antes de extraer..." -ForegroundColor Cyan
        if (-not (Stop-SRSProcesses)) {
            Write-Host "Extraccion cancelada: cierra manualmente SRS-Server.exe y vuelve a intentarlo" -ForegroundColor Red
            return @{ Success = $false }
        }

        Write-Host "Extrayendo el ZIP..." -ForegroundColor White
        Write-Host "Destino: $Destination" -ForegroundColor Gray
        Expand-Archive -Path $ZipPath -DestinationPath $Destination -Force -ErrorAction Stop

        Write-Host "Extraccion completada correctamente!" -ForegroundColor Green
        return @{ Success = $true }
    }
    catch {
        Write-Host "Error durante la extraccion: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Causa probable: archivo SRS sigue en uso. Cierra todos los SRS y vuelve a intentarlo." -ForegroundColor Yellow
        return @{ Success = $false }
    }
}

# === FUNCION 6: Corregir permisos (versión definitiva) ===
function Fix-SRSInstallation {
    param([string]$InstallPath = "C:\Program Files\DCS-SimpleRadio-Standalone")
    Write-Host "Corrigiendo propiedad y permisos al usuario actual..." -ForegroundColor Cyan
    $currentUser = "$env:USERDOMAIN\$env:USERNAME"
    try {
        takeown /F "$InstallPath" /R /D Y | Out-Null
        icacls "$InstallPath" /grant "$($currentUser):(OI)(CI)(F)" /T /C /Q | Out-Null
        icacls "$InstallPath" /grant "Users:(OI)(CI)(RX)" /T /C /Q | Out-Null
        Get-ChildItem -Path $InstallPath -Recurse -File | Unblock-File -ErrorAction SilentlyContinue
        Write-Host "Permisos corregidos correctamente (propiedad al usuario actual)" -ForegroundColor Green
        return @{ Success = $true }
    }
    catch {
        Write-Host "Error al corregir permisos: $($_.Exception.Message)" -ForegroundColor Red
        return @{ Success = $false }
    }
}

# === FUNCION HELPER 7a: GitHub Commits API por archivo (PROTECCION CACHE) ===
function Get-GitHubFileDates {
    param(
        [array]$FileNames,
        [string]$ClientPath = "C:\Program Files\DCS-SimpleRadio-Standalone\Client"
    )

    $logFile   = Join-Path $ClientPath "SRS-GitHub-API-Log.json"
    $cacheFile = Join-Path $ClientPath "SRS-CustomFiles-Cache.json"
    $maxCallsPerHour = 45
    $minSecondsBetweenCalls = 60
    $cacheValidMinutes = 10

    $currentTime = Get-Date
    $remoteDates = @{}
    $logData = @{ Calls = @() }
    $fetchedSuccessfully = $false

    if (Test-Path $logFile) {
        try { 
            $logData = Get-Content $logFile -Raw | ConvertFrom-Json 
            if (-not $logData.PSObject.Properties.Name -contains 'Calls') {
                $logData = @{ Calls = @() }
            }
        } catch { 
            $logData = @{ Calls = @() }
        }
    }

    $recentCalls = @()
    foreach ($ts in $logData.Calls) {
        $callTime = [DateTime]::Parse($ts)
        if (($currentTime - $callTime).TotalMinutes -lt 60) {
            $recentCalls += $callTime
        }
    }

    $lastCallTime = if ($recentCalls.Count -gt 0) { $recentCalls[-1] } else { $null }

    $canMakeAPICall = $true
    if ($recentCalls.Count -ge $maxCallsPerHour) {
        Write-Host "Rate limit alcanzado"
        $canMakeAPICall = $false
    }
    elseif ($lastCallTime -and (($currentTime - $lastCallTime).TotalSeconds -lt $minSecondsBetweenCalls)) {
        Write-Host "Solo 1 llamada por minuto"
        $canMakeAPICall = $false
    }

    # Intentar cache primero
    if (Test-Path $cacheFile) {
        try {
            $cacheData = Get-Content $cacheFile -Raw | ConvertFrom-Json
            $cacheTime = [DateTime]::Parse($cacheData.Timestamp)
            $age = ($currentTime - $cacheTime).TotalMinutes
            if ($age -lt $cacheValidMinutes) {
                foreach ($prop in $cacheData.Dates.PSObject.Properties) {
                    $remoteDates[$prop.Name] = [DateTime]::Parse($prop.Value)
                }
                Write-Host "Cache usado"
                return $remoteDates
            }
        } catch { }
    }

    # Solo si podemos llamar API
    if ($canMakeAPICall) {
        $headers = @{ "User-Agent" = "SRS-Automatic-Installer" }

        foreach ($name in $FileNames) {
            try {
                $apiUrl = "https://api.github.com/repos/LetalDark/DCS-Automatico/commits?path=$name&ref=main&per_page=1"
                Write-Host "DEBUG: Llamando commits para $name"

                $response = Invoke-WebRequest -Uri $apiUrl -Headers $headers -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
                $commits = $response.Content | ConvertFrom-Json

                if ($commits -and $commits.Count -gt 0) {
                    $dateStr = $commits[0].commit.committer.date
                    $parsedDate = [DateTimeOffset]::Parse($dateStr).UtcDateTime.ToLocalTime()
                    $remoteDates[$name] = $parsedDate
                    Write-Host "DEBUG: Fecha obtenida para $name : $parsedDate"
                    $fetchedSuccessfully = $true
                } else {
                    Write-Host "DEBUG: No se obtuvo commit para $name"
                    $remoteDates[$name] = [DateTime]::new(2000,1,1)
                }
            } catch {
                Write-Host "DEBUG: Error en commits para $name : $($_.Exception.Message)"
                $remoteDates[$name] = [DateTime]::new(2000,1,1)
            }
            Start-Sleep -Milliseconds 800
        }

        # SOLO guardar cache si conseguimos al menos una fecha real
        if ($fetchedSuccessfully) {
            $datesObj = [PSCustomObject]@{}
            foreach ($k in $remoteDates.Keys) { $datesObj | Add-Member -NotePropertyName $k -NotePropertyValue $remoteDates[$k].ToString("o") }
            $cacheObj = [PSCustomObject]@{ Timestamp = $currentTime.ToString("o"); Dates = $datesObj }
            $cacheObj | ConvertTo-Json -Depth 10 | Set-Content $cacheFile -Force

            $logData.Calls += $currentTime.ToString("o")
            $logData | ConvertTo-Json -Depth 10 | Set-Content $logFile -Force

            Write-Host "DEBUG: Cache y log guardados (fechas reales obtenidas)"
        } else {
            Write-Host "DEBUG: Rate limit - NO se actualiza cache (se mantiene el anterior)"
        }
    }

    return $remoteDates
}

# === FUNCION 7: Actualizar archivos custom SRS (si no existe = descargar siempre) ===
function Update-CustomSRSFiles {
    param(
        [string]$ClientPath = "C:\Program Files\DCS-SimpleRadio-Standalone\Client"
    )

    Write-Host "`n=== Comprobando archivos personalizados de SRS ===" -ForegroundColor Cyan

    $customFiles = @(
        @{ Name = "awacs-radios-custom.json"; Mandatory = $true },
        @{ Name = "FavouriteServers.csv"; Mandatory = $true },
        @{ Name = "global.cfg"; Mandatory = $false },
        @{ Name = "default.cfg"; Mandatory = $false },
        @{ Name = "general.txt"; Mandatory = $false },
        @{ Name = "intercom.txt"; Mandatory = $false }
    )

    $fileNames = $customFiles | ForEach-Object { $_.Name }

    $remoteDates = Get-GitHubFileDates -FileNames $fileNames -ClientPath $ClientPath

    if ($remoteDates.Count -eq 0) {
        Write-Host "Sin datos remotos disponibles esta vez" -ForegroundColor Yellow
        Write-Host "`nComprobacion de archivos personalizados finalizada" -ForegroundColor Cyan
        return
    }

    foreach ($file in $customFiles) {
        $localFullPath = Join-Path $ClientPath $file.Name
        
        Write-Host "`nProcesando archivo: $($file.Name)" -ForegroundColor Magenta
        Write-Host "Ruta local: $localFullPath" -ForegroundColor White

        $localDate = $null
        if (Test-Path $localFullPath) {
            $localDate = (Get-Item $localFullPath).LastWriteTime
            Write-Host "Fecha LOCAL: $($localDate.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
        } else {
            Write-Host "Fecha LOCAL: No existe el archivo" -ForegroundColor White
        }

        $remoteDate = $null
        if ($remoteDates.ContainsKey($file.Name)) {
            $remoteDate = $remoteDates[$file.Name]
            Write-Host "Fecha REMOTA: $($remoteDate.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
        } else {
            Write-Host "Fecha REMOTA: Archivo no encontrado" -ForegroundColor Red
            continue
        }

        $shouldUpdate = $false

        if (-not $localDate) {
            $shouldUpdate = $true
            Write-Host "DECISION: Archivo no existe localmente -> Se descarga siempre" -ForegroundColor Blue
        }
        elseif ($remoteDate -gt $localDate) {
            $shouldUpdate = $true
            Write-Host "DECISION: Version REMOTA es mas reciente -> Proceder a actualizar" -ForegroundColor Blue
        }
        else {
            Write-Host "DECISION: Archivo local es igual o mas reciente -> No se actualiza" -ForegroundColor Blue
            continue
        }

        if ($shouldUpdate) {
            if (-not $file.Mandatory -and $localDate) {
                Write-Host "Este archivo es OPCIONAL y ya existe localmente" -ForegroundColor Yellow
                Write-Host "Quieres actualizarlo con la version mas reciente? (S/N)" -ForegroundColor Yellow -NoNewline
                $respuesta = Read-Host " "
                if ($respuesta -notmatch '^[sS]') {
                    Write-Host "Usuario cancelo" -ForegroundColor Yellow
                    continue
                }
            } else {
                if (-not $file.Mandatory) {
                    Write-Host "Archivo OPCIONAL pero no existe localmente -> Instalando automaticamente" -ForegroundColor Yellow
                } else {
                    Write-Host "Archivo OBLIGATORIO -> Actualizando automaticamente" -ForegroundColor Yellow
                }
            }

            $url = "https://raw.githubusercontent.com/LetalDark/DCS-Automatico/refs/heads/main/$($file.Name)"
            try {
                Write-Host "Descargando archivo desde GitHub..." -ForegroundColor White
                Invoke-WebRequest -Uri $url -OutFile $localFullPath -UseBasicParsing -TimeoutSec 30
                
                if ($remoteDate) {
                    (Get-Item $localFullPath).LastWriteTime = $remoteDate
                }
                
                Write-Host "Archivo actualizado correctamente" -ForegroundColor Green
            }
            catch {
                Write-Host "ERROR al descargar: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }

    Write-Host "`nComprobacion de archivos personalizados finalizada" -ForegroundColor Cyan
}

# ====================== INICIO DEL SCRIPT ======================

# --- MODO ADMINISTRADOR ---
if ($Elevated) {
    Write-Host "`n[ADMIN] Extrayendo y corrigiendo permisos..." -ForegroundColor Cyan
    $resultadoExtraccion = Expand-SRSZip -ZipPath $ZipPath
    if ($resultadoExtraccion.Success) {
        $fix = Fix-SRSInstallation
        if ($fix.Success) {
            Write-Host "Todo listo! Ya puedes ejecutar SRS desde cualquier usuario sin avisos" -ForegroundColor Green
        }
    }
    exit
}

# --- MODO NORMAL ---
# === Detectar si SR-ClientRadio ya esta abierto ===
if (Test-SRSClientRunning) {
    Write-Host "`nSR-ClientRadio.exe ya esta en ejecucion." -ForegroundColor Yellow
    Write-Host "Cierra el cliente antes de ejecutar este script." -ForegroundColor Yellow
    Write-Host "El script se cerrara ahora." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    exit
}

$accionRealizada = $false
$instalado = Get-SRSInstalled
$ultima = Get-SRSLatestVersion

Write-Host "SRS instalado: " -NoNewline -ForegroundColor Yellow
Write-Host $instalado.Installed -ForegroundColor White

if ($instalado.Installed) {
    Write-Host "Version instalada: " -NoNewline -ForegroundColor Yellow
    Write-Host $instalado.Version -ForegroundColor White
    Write-Host "Ruta: " -NoNewline -ForegroundColor Yellow
    Write-Host $instalado.Path -ForegroundColor White
}
if ($ultima.Success) {
    Write-Host "Ultima version en GitHub: " -NoNewline -ForegroundColor Yellow
    Write-Host $ultima.Version -ForegroundColor White
}

# === LOGICA DE DECISION ===
if (-not $instalado.Installed) {
    Write-Host "SRS no esta instalado. Procediendo con la instalacion automatica..." -ForegroundColor Yellow
    $accionRealizada = $true
} 
elseif ($instalado.Installed -and $ultima.Success -and $instalado.Version -ne $ultima.Version) {
    Write-Host "Hay una version nueva disponible: $($ultima.Version)" -ForegroundColor Yellow
    $respuesta = Read-Host "Quieres actualizar SRS ahora? (S/N)"
    if ($respuesta -match '^[sS]') {
        $accionRealizada = $true
        Write-Host "Actualizacion aceptada por el usuario." -ForegroundColor Green
    } else {
        Write-Host "Actualizacion cancelada por el usuario." -ForegroundColor Yellow
    }
}

# === EJECUCION DE INSTALACION ===
if ($accionRealizada) {
    $descarga = Get-SRSLatestDownloadUrl
    if ($descarga.Success) {
        $resultadoDescarga = Download-SRSLatestZip -DownloadUrl $descarga.DownloadUrl
        if ($resultadoDescarga.Success) {
            if (-not (Test-Admin)) {
                Write-Host "Se requieren permisos de Administrador..." -ForegroundColor Yellow
                Write-Host "Se abrira una ventana que se cerrara sola..."

                try {
                    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Elevated -ZipPath `"$($resultadoDescarga.FilePath)`"" -Verb RunAs -Wait
                    Write-Host "Proceso administrador terminado." -ForegroundColor Cyan
                } catch {
                    if ($_.Exception.Message -like "*usuario ha cancelado*") {
                        Write-Host "El usuario cancelo la elevacion a administrador." -ForegroundColor Yellow
                        Write-Host "Instalacion cancelada por el usuario." -ForegroundColor Yellow
                        $accionRealizada = $false
                    } else {
                        Write-Host "Error al solicitar administrador: $_" -ForegroundColor Red
                    }
                }
            }
        }
    } else {
        Write-Host "No se pudo obtener el enlace de descarga" -ForegroundColor Red
    }
}

# ====================== MENSAJE FINAL + EJECUCION AUTOMATICA ======================
Write-Host "`n--------------------------------------------------" -ForegroundColor DarkGray

$checkFinal = Get-SRSInstalled

if ($checkFinal.Installed) {
    
    if ($accionRealizada) {
        Write-Host "INSTALACION / ACTUALIZACION COMPLETADA CON EXITO!" -ForegroundColor Green
        Write-Host "Version instalada: $($checkFinal.Version)" -ForegroundColor Green
        Write-Host "Ruta: $($checkFinal.Path)" -ForegroundColor Cyan
    } 
    else {
        Write-Host "SRS ya esta instalado y actualizado." -ForegroundColor Green
        # sin repetir version ni ruta para evitar duplicado
    }

Write-Host "--------------------------------------------------" -ForegroundColor DarkGray

    # === ACTUALIZAR ARCHIVOS CUSTOM ANTES DE EJECUTAR SRS ===
    $clientPath = Split-Path $checkFinal.Path -Parent
    Update-CustomSRSFiles -ClientPath $clientPath

    # === EJECUTAR SRS ===
    $exePath = $checkFinal.Path
    $workingDir = Split-Path $exePath -Parent
	Write-Host "`n--------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "Ejecutando DCS-SRS Client..." -ForegroundColor Green
	Write-Host "--------------------------------------------------" -ForegroundColor DarkGray
    Start-Process -FilePath $exePath -WorkingDirectory $workingDir

} 
else {
    Write-Host "La instalacion parece haber fallado" -ForegroundColor Yellow
}