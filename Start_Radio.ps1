param([switch]$Elevated, [string]$ZipPath = "")

# === FIX CONEXION SEGURA ===
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

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

# === FUNCION 5: Extraer ZIP ===
function Expand-SRSZip {
    param([string]$ZipPath, [string]$Destination = "C:\Program Files\DCS-SimpleRadio-Standalone")
    try {
        if (-not (Test-Path $ZipPath)) { Write-Host "Error: ZIP no encontrado" -ForegroundColor Red; return @{ Success = $false } }
        if (-not (Test-Path $Destination)) { New-Item -Path $Destination -ItemType Directory -Force | Out-Null }
        Write-Host "Extrayendo el ZIP..." 
        Write-Host "Destino: $Destination"
        Expand-Archive -Path $ZipPath -DestinationPath $Destination -Force
        Write-Host "Extraccion completada correctamente!" -ForegroundColor Green
        return @{ Success = $true }
    } catch {
        Write-Host "Error durante la extraccion: $_" -ForegroundColor Red
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
        Write-Host "Error al corregir permisos: $_" -ForegroundColor Red
        return @{ Success = $false }
    }
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
$accionRealizada = $false

$instalado = Get-SRSInstalled
$ultima = Get-SRSLatestVersion

Write-Host "SRS instalado: $($instalado.Installed)"
if ($instalado.Installed) {
    Write-Host "Version instalada: $($instalado.Version)"
    Write-Host "Ruta: $($instalado.Path)"
}
if ($ultima.Success) {
    Write-Host "Ultima version en GitHub: $($ultima.Version)"
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
Write-Host "`n--------------------------------------------------"

$checkFinal = Get-SRSInstalled

if ($checkFinal.Installed) {
    if ($accionRealizada) {
        Write-Host "INSTALACION / ACTUALIZACION COMPLETADA CON EXITO!" -ForegroundColor Green
    } else {
        Write-Host "SRS ya esta instalado y actualizado." -ForegroundColor Green
    }
    Write-Host "Version instalada: $($checkFinal.Version)" -ForegroundColor Green
    Write-Host "Ruta: $($checkFinal.Path)" -ForegroundColor Cyan

    # === EJECUTAR DESDE LA CARPETA CORRECTA ===
    $exePath = $checkFinal.Path
    $workingDir = Split-Path $exePath -Parent
    Write-Host "Ejecutando SR-ClientRadio.exe desde su carpeta..." -ForegroundColor Green
    Start-Process -FilePath $exePath -WorkingDirectory $workingDir
} else {
    Write-Host "La instalacion parece haber fallado" -ForegroundColor Yellow
}