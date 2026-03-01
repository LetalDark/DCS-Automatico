# === Start_Radio.ps1 FINAL - TODO EN AppData (SIN ADMIN NUNCA) ===
param()

# === FUNCION COMPACTA: Auto-actualizar SRS-Launcher.cmd ===
function Update-RadioBat {
    $BatUrl = "https://github.com/LetalDark/DCS-Automatico/raw/refs/heads/main/SRS-Launcher.cmd"
    $BatPath = Join-Path (Split-Path $PSCommandPath -Parent) "SRS-Launcher.cmd"
    Write-Host "[AUTO-UPDATE] Comprobando SRS-Launcher.cmd..." -ForegroundColor Cyan
    $tempFile = Join-Path $env:TEMP "SRS-Launcher.cmd.new"
    try {
        Write-Host "[DEBUG] Descargando ultima version de SRS-Launcher.cmd" -ForegroundColor Gray
        Invoke-WebRequest -Uri $BatUrl -OutFile $tempFile -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
        $needsUpdate = $true
        if (Test-Path $BatPath) {
            Write-Host "[DEBUG] Comparando contenido con version local..." -ForegroundColor Gray
            $tempContent = Get-Content $tempFile -Raw
            $localContent = Get-Content $BatPath -Raw
            if ($tempContent.Trim() -eq $localContent.Trim()) {
                $needsUpdate = $false
            }
        }
        if ($needsUpdate) {
            Write-Host "[INFO] Actualizando SRS-Launcher.cmd..." -ForegroundColor Yellow
            Copy-Item $tempFile $BatPath -Force
            Write-Host "[OK] SRS-Launcher.cmd actualizado correctamente" -ForegroundColor Green
        } else {
            Write-Host "[OK] SRS-Launcher.cmd ya esta al dia" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "[ERROR] No se pudo actualizar SRS-Launcher.cmd: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    }
}

# === FUNCION AUXILIAR: Cerrar procesos SRS ===
function Stop-SRSProcesses {
    Write-Host "[DEBUG] Iniciando Stop-SRSProcesses..." -ForegroundColor Gray
    $processes = @("SR-ClientRadio", "SRS-Server")
    Write-Host "[DEBUG] Procesos a cerrar: $($processes -join ', ')" -ForegroundColor Gray
    $allStopped = $true
    foreach ($procName in $processes) {
        Write-Host "[DEBUG] Revisando proceso: $procName" -ForegroundColor Gray
        $running = Get-Process -Name $procName -ErrorAction SilentlyContinue
        if ($running) {
            Write-Host "Detectado proceso $procName.exe en ejecucion..." -ForegroundColor Yellow
            try {
                Write-Host "[DEBUG] Intentando cerrar $procName.exe (PID: $($running.Id))" -ForegroundColor Gray
                $running | Stop-Process -Force -ErrorAction Stop
                Start-Sleep -Seconds 1.5
                $stillRunning = Get-Process -Name $procName -ErrorAction SilentlyContinue
                if ($stillRunning) {
                    Write-Host "[DEBUG] Proceso $procName.exe sigue vivo despues de Stop-Process" -ForegroundColor Yellow
                    $allStopped = $false
                } else {
                    Write-Host " -> $procName.exe cerrado correctamente" -ForegroundColor Green
                }
            } catch {
                Write-Host " -> No se pudo cerrar $procName.exe automaticamente" -ForegroundColor Red
                Write-Host "[ERROR] Detalle: $($_.Exception.Message)" -ForegroundColor Red
                $allStopped = $false
            }
        } else {
            Write-Host "[DEBUG] Proceso $procName.exe no estaba en ejecucion" -ForegroundColor Gray
        }
    }
    Write-Host "[DEBUG] Stop-SRSProcesses finalizado. Todos cerrados: $allStopped" -ForegroundColor Gray
    return $allStopped
}

# === FUNCION: Detectar si SR-ClientRadio esta abierto (solo detecta) ===
function Test-SRSClientRunning {
    Write-Host "[DEBUG] Iniciando Test-SRSClientRunning..." -ForegroundColor Gray
    Write-Host "[DEBUG] Buscando proceso exacto: SR-ClientRadio" -ForegroundColor Gray
    $proc = Get-Process -Name "SR-ClientRadio" -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Host "[DEBUG] Proceso SR-ClientRadio encontrado (PID: $($proc.Id))" -ForegroundColor Yellow
        Write-Host "SR-ClientRadio.exe ya esta en ejecucion." -ForegroundColor Yellow
        Write-Host "[DEBUG] Test-SRSClientRunning retorna: TRUE" -ForegroundColor Gray
        return $true
    } else {
        Write-Host "[DEBUG] Proceso SR-ClientRadio NO encontrado" -ForegroundColor Gray
        Write-Host "[DEBUG] Test-SRSClientRunning retorna: FALSE" -ForegroundColor Gray
        return $false
    }
}

# === FUNCION 1: Comprobar SRS instalado ===
function Get-SRSInstalled {
    Write-Host "[DEBUG] Iniciando Get-SRSInstalled..." -ForegroundColor Gray
    $baseFolder = Join-Path $env:LOCALAPPDATA "DCS-SimpleRadio-Standalone\Client"
    $path = Join-Path $baseFolder "SR-ClientRadio.exe"
    Write-Host "[DEBUG] Ruta que se esta revisando: $path" -ForegroundColor Gray
    if (Test-Path $path) {
        Write-Host "[DEBUG] Archivo SR-ClientRadio.exe encontrado en AppData" -ForegroundColor Green
        $version = (Get-Item $path).VersionInfo.ProductVersion
        Write-Host "[DEBUG] Version detectada: $version" -ForegroundColor Gray
        Write-Host "[DEBUG] Get-SRSInstalled retorna: Installed = true" -ForegroundColor Gray
        return @{ Installed = $true; Version = $version; Path = $path }
    } else {
        Write-Host "[DEBUG] Archivo SR-ClientRadio.exe NO encontrado en AppData" -ForegroundColor Gray
        Write-Host "[DEBUG] Get-SRSInstalled retorna: Installed = false" -ForegroundColor Gray
        return @{ Installed = $false; Version = $null; Path = $null }
    }
}

# === FUNCION 2: Obtener ultima version ===
function Get-SRSLatestVersion {
    Write-Host "[DEBUG] Iniciando Get-SRSLatestVersion..." -ForegroundColor Gray
    Write-Host "[DEBUG] Consultando GitHub releases/latest..." -ForegroundColor Gray
    try {
        $response = Invoke-WebRequest -Uri "https://github.com/ciribob/DCS-SimpleRadioStandalone/releases/latest" -UseBasicParsing
        $version = $response.BaseResponse.ResponseUri.AbsoluteUri.Split('/')[-1].TrimStart('v')
        Write-Host "[DEBUG] Version obtenida de GitHub: $version" -ForegroundColor Green
        Write-Host "[DEBUG] Get-SRSLatestVersion retorna: Success = true" -ForegroundColor Gray
        return @{ Success = $true; Version = $version }
    } catch {
        Write-Host "[ERROR] No se pudo obtener la version de GitHub: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[DEBUG] Get-SRSLatestVersion retorna: Success = false" -ForegroundColor Gray
        return @{ Success = $false; Version = $null }
    }
}

# === FUNCION 3: Obtener ultimo enlace de descarga ===
function Get-SRSLatestDownloadUrl {
    Write-Host "[DEBUG] Iniciando Get-SRSLatestDownloadUrl..." -ForegroundColor Gray
    Write-Host "[DEBUG] Consultando GitHub releases/latest para obtener enlace de descarga..." -ForegroundColor Gray
    try {
        $response = Invoke-WebRequest -Uri "https://github.com/ciribob/DCS-SimpleRadioStandalone/releases/latest" -UseBasicParsing
        $version = $response.BaseResponse.ResponseUri.AbsoluteUri.Split('/')[-1].TrimStart('v')
        $downloadUrl = "https://github.com/ciribob/DCS-SimpleRadioStandalone/releases/download/$version/DCS-SimpleRadioStandalone-$version.zip"
        Write-Host "[DEBUG] Version obtenida: $version" -ForegroundColor Green
        Write-Host "[DEBUG] URL de descarga construida: $downloadUrl" -ForegroundColor Gray
        Write-Host "[DEBUG] Get-SRSLatestDownloadUrl retorna: Success = true" -ForegroundColor Gray
        return @{ Success = $true; Version = $version; DownloadUrl = $downloadUrl }
    } catch {
        Write-Host "[ERROR] No se pudo obtener el enlace de GitHub: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[DEBUG] Get-SRSLatestDownloadUrl retorna: Success = false" -ForegroundColor Gray
        return @{ Success = $false; Version = $null; DownloadUrl = $null }
    }
}

# === FUNCION 4: Descargar ZIP ===
function Download-SRSLatestZip {
    param([string]$DownloadUrl)
    Write-Host "[DEBUG] Iniciando Download-SRSLatestZip..." -ForegroundColor Gray
    $baseFolder = Join-Path $env:LOCALAPPDATA "DCS-SimpleRadio-Standalone"
    $destinationFolder = Join-Path $baseFolder "temp"
    $fileName = [System.IO.Path]::GetFileName($DownloadUrl)
    $destinationPath = Join-Path $destinationFolder $fileName
    $minSizeBytes = 265MB
    Write-Host "[DEBUG] Carpeta destino: $destinationFolder" -ForegroundColor Gray
    Write-Host "[DEBUG] Archivo ZIP que se va a guardar: $destinationPath" -ForegroundColor Gray
    try {
        if (-not (Test-Path $destinationFolder)) {
            Write-Host "[DEBUG] Creando carpeta temp en AppData..." -ForegroundColor Gray
            New-Item -Path $destinationFolder -ItemType Directory -Force | Out-Null
        }
        if (Test-Path $destinationPath) {
            $size = (Get-Item $destinationPath).Length
            if ($size -lt $minSizeBytes) {
                Write-Host "ZIP encontrado pero corrupto ($([math]::Round($size/1MB,1)) MB). Se borra y se vuelve a descargar." -ForegroundColor Yellow
                Write-Host "[DEBUG] Borrando ZIP corrupto..." -ForegroundColor Gray
                Remove-Item $destinationPath -Force
            } else {
                Write-Host "El ZIP ya existe y parece correcto ($([math]::Round($size/1MB,1)) MB). Se omite la descarga." -ForegroundColor Cyan
                Write-Host "[DEBUG] Download-SRSLatestZip retorna: Success = true (usando cache)" -ForegroundColor Gray
                return @{ Success = $true; FilePath = $destinationPath }
            }
        }
        Write-Host "Descargando SRS ZIP..." -ForegroundColor White
        Write-Host "Destino: $destinationPath" -ForegroundColor Gray
        Write-Host "[DEBUG] Iniciando descarga desde: $DownloadUrl" -ForegroundColor Gray
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $destinationPath -UseBasicParsing
        $size = (Get-Item $destinationPath).Length
        if ($size -lt $minSizeBytes) {
            Write-Host "Descarga terminada pero parece corrupto ($([math]::Round($size/1MB,1)) MB)" -ForegroundColor Red
            Write-Host "[DEBUG] Borrando ZIP corrupto despues de descarga..." -ForegroundColor Gray
            Remove-Item $destinationPath -Force -ErrorAction SilentlyContinue
            Write-Host "[DEBUG] Download-SRSLatestZip retorna: Success = false" -ForegroundColor Gray
            return @{ Success = $false; FilePath = $null }
        }
        Write-Host "Descarga completada correctamente! ($([math]::Round($size/1MB,1)) MB)" -ForegroundColor Green
        Write-Host "[DEBUG] Download-SRSLatestZip retorna: Success = true" -ForegroundColor Gray
        return @{ Success = $true; FilePath = $destinationPath }
    } catch {
        Write-Host "Error al descargar: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[DEBUG] Download-SRSLatestZip retorna: Success = false (excepcion)" -ForegroundColor Gray
        return @{ Success = $false; FilePath = $null }
    }
}

# === FUNCION 5: Extraer ZIP (TODO menos carpetas Server) ===
function Expand-SRSZip {
    param([string]$ZipPath)
    Write-Host "[DEBUG] Iniciando Expand-SRSZip (todo menos Server)..." -ForegroundColor Gray
    $destination = Join-Path $env:LOCALAPPDATA "DCS-SimpleRadio-Standalone"
    Write-Host "[DEBUG] Carpeta destino de instalacion: $destination" -ForegroundColor Gray
    try {
        if (-not (Test-Path $ZipPath)) {
            Write-Host "Error: ZIP no encontrado" -ForegroundColor Red
            Write-Host "[DEBUG] Expand-SRSZip retorna: Success = false (ZIP no existe)" -ForegroundColor Gray
            return @{ Success = $false }
        }
        if (-not (Test-Path $destination)) {
            Write-Host "[DEBUG] Creando carpeta principal en AppData..." -ForegroundColor Gray
            New-Item -Path $destination -ItemType Directory -Force | Out-Null
        }
        Write-Host "Comprobando procesos SRS antes de extraer..." -ForegroundColor Cyan
        if (-not (Stop-SRSProcesses)) {
            Write-Host "Extraccion cancelada: cierra manualmente SRS-Server.exe y vuelve a intentarlo" -ForegroundColor Red
            Write-Host "[DEBUG] Expand-SRSZip retorna: Success = false (procesos no cerrados)" -ForegroundColor Gray
            return @{ Success = $false }
        }
        Write-Host "Extrayendo el ZIP completo..." -ForegroundColor White
        Write-Host "Destino: $destination" -ForegroundColor Gray
        Write-Host "[DEBUG] Ejecutando Expand-Archive (todo el contenido)..." -ForegroundColor Gray
        Expand-Archive -Path $ZipPath -DestinationPath $destination -Force -ErrorAction Stop
        # === BORRAR SOLO LAS CARPETAS SERVER (lo que no quieres) ===
        $unwantedFolders = @("Server", "ServerCommandLine-Linux", "ServerCommandLine-Windows")
        foreach ($folder in $unwantedFolders) {
            $fullPath = Join-Path $destination $folder
            if (Test-Path $fullPath) {
                Write-Host "[DEBUG] Borrando carpeta no deseada: $folder" -ForegroundColor Gray
                Remove-Item $fullPath -Recurse -Force
            }
        }
        Write-Host "Extraccion completada correctamente!" -ForegroundColor Green
        Write-Host "-> Se han eliminado las carpetas Server (no necesarias)" -ForegroundColor Cyan
        Write-Host "[DEBUG] Expand-SRSZip retorna: Success = true" -ForegroundColor Gray
        return @{ Success = $true }
    }
    catch {
        Write-Host "Error durante la extraccion: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Causa probable: archivo SRS sigue en uso. Cierra todos los SRS y vuelve a intentarlo." -ForegroundColor Yellow
        Write-Host "[DEBUG] Expand-SRSZip retorna: Success = false (excepcion)" -ForegroundColor Gray
        return @{ Success = $false }
    }
}

# === FUNCION 6: Corregir permisos (versión definitiva) ===
function Fix-SRSInstallation {
    Write-Host "[DEBUG] Iniciando Fix-SRSInstallation (solo Unblock-File)..." -ForegroundColor Gray
    $installPath = Join-Path $env:LOCALAPPDATA "DCS-SimpleRadio-Standalone"
    Write-Host "[DEBUG] Carpeta principal en AppData: $installPath" -ForegroundColor Gray
    try {
        if (Test-Path $installPath) {
            Write-Host "[DEBUG] Aplicando Unblock-File a todos los archivos..." -ForegroundColor Gray
            Get-ChildItem -Path $installPath -Recurse -File -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
            Write-Host "[DEBUG] Unblock-File completado en todos los archivos" -ForegroundColor Gray
            Write-Host "[OK] Archivos desbloqueados correctamente" -ForegroundColor Green
        } else {
            Write-Host "[DEBUG] Carpeta principal aun no existe (se creara durante la extraccion)" -ForegroundColor Gray
            Write-Host "[OK] No hay archivos que desbloquear aun" -ForegroundColor Green
        }
        Write-Host "[DEBUG] Fix-SRSInstallation retorna: Success = true" -ForegroundColor Gray
        return @{ Success = $true }
    }
    catch {
        Write-Host "[ERROR] Error al desbloquear archivos: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[DEBUG] Fix-SRSInstallation retorna: Success = false (excepcion)" -ForegroundColor Gray
        return @{ Success = $false }
    }
}

# === FUNCION HELPER 7a: GitHub Commits API por archivo (PROTECCION CACHE) ===
function Get-GitHubFileDates {
    param(
        [array]$FileNames,
        [string]$ClientPath = ""
    )
    Write-Host "[DEBUG] Iniciando Get-GitHubFileDates..." -ForegroundColor Gray
    # === USAR CARPETA AppData si no se pasa parametro ===
    if (-not $ClientPath) {
        $ClientPath = Join-Path $env:LOCALAPPDATA "DCS-SimpleRadio-Standalone\Client"
        Write-Host "[DEBUG] Usando ClientPath por defecto en AppData: $ClientPath" -ForegroundColor Gray
    } else {
        Write-Host "[DEBUG] ClientPath recibido por parametro: $ClientPath" -ForegroundColor Gray
    }
    $logFile = Join-Path $ClientPath "SRS-GitHub-API-Log.json"
    $cacheFile = Join-Path $ClientPath "SRS-CustomFiles-Cache.json"
    $maxCallsPerHour = 45
    $minSecondsBetweenCalls = 60
    $cacheValidMinutes = 10
    $currentTime = Get-Date
    $remoteDates = @{}
    $logData = @{ Calls = @() }
    $fetchedSuccessfully = $false
    Write-Host "[DEBUG] logFile: $logFile" -ForegroundColor Gray
    Write-Host "[DEBUG] cacheFile: $cacheFile" -ForegroundColor Gray
    # === Cargar log existente ===
    if (Test-Path $logFile) {
        try {
            $logData = Get-Content $logFile -Raw | ConvertFrom-Json
            if (-not $logData.PSObject.Properties.Name -contains 'Calls') {
                $logData = @{ Calls = @() }
            }
            Write-Host "[DEBUG] Log cargado correctamente" -ForegroundColor Gray
        } catch {
            $logData = @{ Calls = @() }
            Write-Host "[DEBUG] Error al leer log, se crea nuevo" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[DEBUG] No existe logFile aun, se creara nuevo" -ForegroundColor Gray
    }
    # === Filtrar llamadas recientes (ultima hora) ===
    $recentCalls = @()
    foreach ($ts in $logData.Calls) {
        try {
            $callTime = [DateTime]::Parse($ts)
            if (($currentTime - $callTime).TotalMinutes -lt 60) {
                $recentCalls += $callTime
            }
        } catch { }
    }
    $lastCallTime = if ($recentCalls.Count -gt 0) { $recentCalls[-1] } else { $null }
    $canMakeAPICall = $true
    if ($recentCalls.Count -ge $maxCallsPerHour) {
        Write-Host "[DEBUG] Rate limit alcanzado (45 llamadas/hora)" -ForegroundColor Yellow
        $canMakeAPICall = $false
    }
    elseif ($lastCallTime -and (($currentTime - $lastCallTime).TotalSeconds -lt $minSecondsBetweenCalls)) {
        Write-Host "[DEBUG] Solo 1 llamada por minuto (espera activa)" -ForegroundColor Yellow
        $canMakeAPICall = $false
    }
    Write-Host "[DEBUG] Podemos llamar API: $canMakeAPICall" -ForegroundColor Gray
    # === Intentar cache primero ===
    if (Test-Path $cacheFile) {
        try {
            $cacheData = Get-Content $cacheFile -Raw | ConvertFrom-Json
            $cacheTime = [DateTime]::Parse($cacheData.Timestamp)
            $age = ($currentTime - $cacheTime).TotalMinutes
            if ($age -lt $cacheValidMinutes) {
                foreach ($prop in $cacheData.Dates.PSObject.Properties) {
                    $remoteDates[$prop.Name] = [DateTime]::Parse($prop.Value)
                }
                Write-Host "[DEBUG] Cache valido usado (edad: $([math]::Round($age,1)) min)" -ForegroundColor Green
                Write-Host "[DEBUG] Get-GitHubFileDates retorna cache (sin llamar API)" -ForegroundColor Gray
                return $remoteDates
            } else {
                Write-Host "[DEBUG] Cache expirado, se intentara API" -ForegroundColor Gray
            }
        } catch {
            Write-Host "[DEBUG] Error al leer cache, se intentara API" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[DEBUG] No existe cache aun" -ForegroundColor Gray
    }
    # === Solo si podemos llamar API ===
    if ($canMakeAPICall) {
        $headers = @{ "User-Agent" = "SRS-Automatic-Installer" }
        Write-Host "[DEBUG] Iniciando llamadas a GitHub API para $($FileNames.Count) archivos..." -ForegroundColor Gray
        foreach ($name in $FileNames) {
            try {
                $apiUrl = "https://api.github.com/repos/LetalDark/DCS-Automatico/commits?path=$name&ref=main&per_page=1"
                Write-Host "[DEBUG] Llamando API para: $name" -ForegroundColor Gray
                $response = Invoke-WebRequest -Uri $apiUrl -Headers $headers -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
                $commits = $response.Content | ConvertFrom-Json
                if ($commits -and $commits.Count -gt 0) {
                    $dateStr = $commits[0].commit.committer.date
                    $parsedDate = [DateTimeOffset]::Parse($dateStr).UtcDateTime.ToLocalTime()
                    $remoteDates[$name] = $parsedDate
                    Write-Host "[DEBUG] Fecha REMOTA para $name : $parsedDate" -ForegroundColor Green
                    $fetchedSuccessfully = $true
                } else {
                    Write-Host "[DEBUG] No se obtuvo commit para $name" -ForegroundColor Yellow
                    $remoteDates[$name] = [DateTime]::new(2000,1,1)
                }
            } catch {
                Write-Host "[DEBUG] Error en API para $name : $($_.Exception.Message)" -ForegroundColor Red
                $remoteDates[$name] = [DateTime]::new(2000,1,1)
            }
            Start-Sleep -Milliseconds 800
        }
        # === Guardar cache SOLO si conseguimos datos reales ===
        if ($fetchedSuccessfully) {
            $datesObj = [PSCustomObject]@{}
            foreach ($k in $remoteDates.Keys) { 
                $datesObj | Add-Member -NotePropertyName $k -NotePropertyValue $remoteDates[$k].ToString("o") 
            }
            $cacheObj = [PSCustomObject]@{ Timestamp = $currentTime.ToString("o"); Dates = $datesObj }
            $cacheObj | ConvertTo-Json -Depth 10 | Set-Content $cacheFile -Force
            $logData.Calls += $currentTime.ToString("o")
            $logData | ConvertTo-Json -Depth 10 | Set-Content $logFile -Force
            Write-Host "[DEBUG] Cache y log guardados correctamente" -ForegroundColor Green
        } else {
            Write-Host "[DEBUG] NO se guardo cache (rate limit o errores)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[DEBUG] No se llamo API por rate limit" -ForegroundColor Yellow
    }
    Write-Host "[DEBUG] Get-GitHubFileDates finalizado. Fechas obtenidas: $($remoteDates.Count)" -ForegroundColor Gray
    return $remoteDates
}

# === FUNCION 7: Actualizar archivos custom SRS (si no existe = descargar siempre) ===
function Update-CustomSRSFiles {
    param(
        [string]$ClientPath = ""
    )
    Write-Host "[DEBUG] Iniciando Update-CustomSRSFiles..." -ForegroundColor Gray
    # === USAR AppData si no se pasa parametro ===
    if (-not $ClientPath) {
        $ClientPath = Join-Path $env:LOCALAPPDATA "DCS-SimpleRadio-Standalone\Client"
        Write-Host "[DEBUG] ClientPath por defecto (AppData): $ClientPath" -ForegroundColor Gray
    } else {
        Write-Host "[DEBUG] ClientPath recibido: $ClientPath" -ForegroundColor Gray
    }
    if (-not (Test-Path $ClientPath)) {
        Write-Host "[DEBUG] Creando carpeta Client en AppData..." -ForegroundColor Gray
        New-Item -Path $ClientPath -ItemType Directory -Force | Out-Null
    }
    Write-Host "`n=== Comprobando archivos personalizados de SRS ===" -ForegroundColor Cyan
    $customFiles = @(
        @{ Name = "awacs-radios-custom.json"; Mandatory = $true },
        @{ Name = "FavouriteServers.csv"; Mandatory = $true },
        @{ Name = "global.cfg"; Mandatory = $false },
        @{ Name = "default.cfg"; Mandatory = $false },
        @{ Name = "Global.txt"; Mandatory = $true },
		@{ Name = "Comandancia.txt"; Mandatory = $true },
		@{ Name = "Flotas.txt"; Mandatory = $true },
		@{ Name = "Naves.txt"; Mandatory = $true },
		@{ Name = "Tripulacion.txt"; Mandatory = $true },
		@{ Name = "Terrestre.txt"; Mandatory = $true },
		@{ Name = "Equipo-Terrestre.txt"; Mandatory = $true },
		@{ Name = "Otros.txt"; Mandatory = $true }
    )
    $fileNames = $customFiles | ForEach-Object { $_.Name }
    Write-Host "[DEBUG] Archivos a comprobar: $($fileNames -join ', ')" -ForegroundColor Gray
    $remoteDates = Get-GitHubFileDates -FileNames $fileNames -ClientPath $ClientPath
    if ($remoteDates.Count -eq 0) {
        Write-Host "Sin datos remotos disponibles esta vez" -ForegroundColor Yellow
        Write-Host "`nComprobacion de archivos personalizados finalizada" -ForegroundColor Cyan
        Write-Host "[DEBUG] Update-CustomSRSFiles finalizado sin datos remotos" -ForegroundColor Gray
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
            Write-Host "[DEBUG] Archivo existe localmente" -ForegroundColor Gray
        } else {
            Write-Host "Fecha LOCAL: No existe el archivo" -ForegroundColor White
            Write-Host "[DEBUG] Archivo NO existe localmente" -ForegroundColor Gray
        }
        $remoteDate = $null
        if ($remoteDates.ContainsKey($file.Name)) {
            $remoteDate = $remoteDates[$file.Name]
            Write-Host "Fecha REMOTA: $($remoteDate.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
            Write-Host "[DEBUG] Fecha remota obtenida" -ForegroundColor Gray
        } else {
            Write-Host "Fecha REMOTA: Archivo no encontrado" -ForegroundColor Red
            Write-Host "[DEBUG] No hay fecha remota para este archivo" -ForegroundColor Gray
            continue
        }
        $shouldUpdate = $false
        if (-not $localDate) {
            $shouldUpdate = $true
            Write-Host "DECISION: Archivo no existe localmente -> Se descarga siempre" -ForegroundColor Blue
            Write-Host "[DEBUG] Decision: descargar (no existe)" -ForegroundColor Gray
        }
        elseif ($remoteDate -gt $localDate) {
            $shouldUpdate = $true
            Write-Host "DECISION: Version REMOTA es mas reciente -> Proceder a actualizar" -ForegroundColor Blue
            Write-Host "[DEBUG] Decision: actualizar (remota mas nueva)" -ForegroundColor Gray
        }
        else {
            Write-Host "DECISION: Archivo local es igual o mas reciente -> No se actualiza" -ForegroundColor Blue
            Write-Host "[DEBUG] Decision: no actualizar" -ForegroundColor Gray
            continue
        }
        if ($shouldUpdate) {
            if (-not $file.Mandatory -and $localDate) {
                Write-Host "Este archivo es OPCIONAL y ya existe localmente" -ForegroundColor Yellow
                Write-Host "Quieres actualizarlo con la version mas reciente? (S/N)" -ForegroundColor Yellow -NoNewline
                $respuesta = Read-Host " "
                if ($respuesta -notmatch '^[sS]') {
                    Write-Host "Usuario cancelo" -ForegroundColor Yellow
                    Write-Host "[DEBUG] Usuario cancelo actualizacion opcional" -ForegroundColor Gray
                    continue
                }
            } else {
                if (-not $file.Mandatory) {
                    Write-Host "Archivo OPCIONAL pero no existe localmente -> Instalando automaticamente" -ForegroundColor Yellow
                    Write-Host "[DEBUG] Instalando opcional que no existia" -ForegroundColor Gray
                } else {
                    Write-Host "Archivo OBLIGATORIO -> Actualizando automaticamente" -ForegroundColor Yellow
                    Write-Host "[DEBUG] Actualizando obligatorio" -ForegroundColor Gray
                }
            }
            $url = "https://raw.githubusercontent.com/LetalDark/DCS-Automatico/refs/heads/main/$($file.Name)"
            try {
                Write-Host "Descargando archivo desde GitHub..." -ForegroundColor White
                Write-Host "[DEBUG] URL: $url" -ForegroundColor Gray
                Invoke-WebRequest -Uri $url -OutFile $localFullPath -UseBasicParsing -TimeoutSec 30
                if ($remoteDate) {
                    (Get-Item $localFullPath).LastWriteTime = $remoteDate
                    Write-Host "[DEBUG] Fecha del archivo actualizada a remota" -ForegroundColor Gray
                }
                Write-Host "Archivo actualizado correctamente" -ForegroundColor Green
                Write-Host "[DEBUG] Descarga y guardado OK" -ForegroundColor Gray
            }
            catch {
                Write-Host "ERROR al descargar: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "[DEBUG] Error en descarga" -ForegroundColor Red
            }
        }
    }
    Write-Host "`nComprobacion de archivos personalizados finalizada" -ForegroundColor Cyan
    Write-Host "[DEBUG] Update-CustomSRSFiles finalizado completamente" -ForegroundColor Gray
}

# === FUNCION 8: Crear/Actualizar acceso directo en Escritorio con icono Yokai ===
function Create-DesktopShortcut {
    Write-Host "[DEBUG] Iniciando Create-DesktopShortcut..." -ForegroundColor Gray

    $desktop = [Environment]::GetFolderPath("Desktop")
    $shortcutPath = Join-Path $desktop "SRS Yokai Radio.lnk"
    $targetCmd = Join-Path $env:LOCALAPPDATA "DCS-SimpleRadio-Standalone\Client\SRS-Launcher.cmd"
    $iconPath   = Join-Path $env:LOCALAPPDATA "DCS-SimpleRadio-Standalone\Client\Yokai-SRS.ico"

    # 1. Solo se ejecuta si SRS está instalado
    if (-not (Get-SRSInstalled).Installed) {
        Write-Host "[DEBUG] SRS no instalado → no se crea acceso directo" -ForegroundColor Gray
        return
    }

    # 2. Descargar icono si no existe (siempre se asegura de tenerlo)
    $icoUrl = "https://github.com/LetalDark/DCS-Automatico/raw/refs/heads/main/Yokai-SRS.ico"
    if (-not (Test-Path $iconPath)) {
        Write-Host "[DEBUG] Descargando Yokai-SRS.ico..." -ForegroundColor Gray
        try {
            Invoke-WebRequest -Uri $icoUrl -OutFile $iconPath -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
            Write-Host "[OK] Icono Yokai descargado correctamente" -ForegroundColor Green
        } catch {
            Write-Host "[ERROR] No se pudo descargar el icono (se creará shortcut sin icono)" -ForegroundColor Red
        }
    } else {
        Write-Host "[DEBUG] Icono Yokai-SRS.ico ya existe" -ForegroundColor Gray
    }

    # 3. Crear o actualizar el acceso directo
    try {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $targetCmd
        $shortcut.WorkingDirectory = Split-Path $targetCmd -Parent
        $shortcut.IconLocation = "$iconPath,0"
        $shortcut.Save()

        if (Test-Path $shortcutPath) {
            Write-Host "[OK] Acceso directo 'SRS Yokai Radio.lnk' creado/actualizado correctamente con icono Yokai" -ForegroundColor Green
        }
    } catch {
        Write-Host "[ERROR] No se pudo crear/actualizar el acceso directo: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ====================== INICIO DEL SCRIPT ======================

# Actualizar el launcher antes de continuar
Update-RadioBat

# === FIX CONEXION SEGURA ===
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

Write-Host "[DEBUG] === INICIO DEL SCRIPT PRINCIPAL ===" -ForegroundColor Gray
Write-Host "[DEBUG] Usando carpeta completa en AppData: $env:LOCALAPPDATA\DCS-SimpleRadio-Standalone" -ForegroundColor Gray

# === Detectar si SR-ClientRadio ya esta abierto ===
if (Test-SRSClientRunning) {
    Write-Host "`nSR-ClientRadio.exe ya esta en ejecucion." -ForegroundColor Yellow
    Write-Host "Cierra el cliente antes de ejecutar este script." -ForegroundColor Yellow
    Write-Host "El script se cerrara ahora." -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    exit
}

$accionRealizada = $false

# === Obtener estado actual ===
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

# === EJECUCION DE INSTALACION (sin elevacion) ===
if ($accionRealizada) {
    Write-Host "[DEBUG] Iniciando proceso de descarga e instalacion..." -ForegroundColor Gray
    $descarga = Get-SRSLatestDownloadUrl
    if ($descarga.Success) {
        $resultadoDescarga = Download-SRSLatestZip -DownloadUrl $descarga.DownloadUrl
        if ($resultadoDescarga.Success) {
            Write-Host "[DEBUG] ZIP descargado correctamente, procediendo a extraer..." -ForegroundColor Gray
            $resultadoExtraccion = Expand-SRSZip -ZipPath $resultadoDescarga.FilePath
            if ($resultadoExtraccion.Success) {
                Write-Host "[DEBUG] Extraccion OK, aplicando Fix..." -ForegroundColor Gray
                $fix = Fix-SRSInstallation
                if ($fix.Success) {
                    Write-Host "[DEBUG] Instalacion completada sin necesidad de administrador" -ForegroundColor Green
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
    } else {
        Write-Host "SRS ya esta instalado y actualizado." -ForegroundColor Green
    }
    Write-Host "--------------------------------------------------" -ForegroundColor DarkGray

    # === ACTUALIZAR ARCHIVOS CUSTOM ANTES DE EJECUTAR SRS ===
    $clientPath = Split-Path $checkFinal.Path -Parent
    Write-Host "[DEBUG] Actualizando archivos personalizados en: $clientPath" -ForegroundColor Gray
    Update-CustomSRSFiles -ClientPath $clientPath

    # === EJECUTAR SRS ===
    $exePath = $checkFinal.Path
    $workingDir = Split-Path $exePath -Parent
    Write-Host "`n--------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "Ejecutando DCS-SRS Client..." -ForegroundColor Green
    Write-Host "--------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "[DEBUG] Ejecutando: $exePath" -ForegroundColor Gray
    Write-Host "[DEBUG] Directorio de trabajo: $workingDir" -ForegroundColor Gray
    Start-Process -FilePath $exePath -WorkingDirectory $workingDir
} else {
    Write-Host "La instalacion parece haber fallado" -ForegroundColor Yellow
}

# === Crear acceso directo en Escritorio (solo primera vez) ===
Create-DesktopShortcut

Write-Host "[DEBUG] === FIN DEL SCRIPT PRINCIPAL ===" -ForegroundColor Gray
