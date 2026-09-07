<#
.SYNOPSIS
    Custom convoluted PowerShell based encryption/decryption algorithm for files and folders.

.DESCRIPTION
    Encrypts or decrypts files and entire folders using a custom algorithm.

.PARAMETER Encrypt
    Switch to Encrypt files.

.PARAMETER Decrypt
    Switch to Decrypt files.

.PARAMETER Path
    Path to file or folder to encrypt/decrypt.

.PARAMETER Key
    Integer based key to encrypt/decrypt; maximum value is 2147483647.

.PARAMETER Recursive
    Process subdirectories recursively.

.PARAMETER Extension
    Extension to use for encrypted files (default: .encrypted).

.EXAMPLE
    .\Fucky64.ps1 -Encrypt -Path "C:\folder\file.txt" -Key 12345

.EXAMPLE
    .\Fucky64.ps1 -Decrypt -Path "C:\folder\file.txt.encrypted" -Key 12345

.EXAMPLE
    .\Fucky64.ps1 -Encrypt -Path "C:\folder" -Key 12345 -Recursive

.EXAMPLE
    .\Fucky64.ps1 -Decrypt -Path "C:\folder" -Key 12345 -Recursive -Extension ".encrypted"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, ParameterSetName='Encrypt')]
    [switch]$Encrypt,

    [Parameter(Mandatory=$true, ParameterSetName='Decrypt')]
    [switch]$Decrypt,

    [Parameter(Mandatory=$true)]
    [string]$Path,

    [Parameter(Mandatory=$false)]
    [int]$Key,

    [Parameter(Mandatory=$false)]
    [switch]$Recursive,

    [Parameter(Mandatory=$false)]
    [string]$Extension = '.encrypted'
)

# Validar que la ruta existe
if (-not (Test-Path $Path)) {
    Write-Error "Path not found: $Path"
    exit 1
}

# Validar Key
if ($Key) {
    if ($Key -gt 2147483647 -or $Key -lt 0) {
        Write-Error "Key must be between 0 and 2147483647."
        exit 1
    }
}

# Función para cifrar contenido
function Invoke-Encryption {
    param([string]$Content)
    
    Write-Verbose "Encrypting content..."
    
    # Paso 1: Convertir a Base64
    $Step1 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Content))
    
    # Paso 2: Reemplazar caracteres especiales
    $Step2 = $Step1 -replace '\+', '!' -replace '/', '-' -replace '=', '*'
    
    # Paso 3: Separar en arrays pares/impares
    $EvenChars = @()
    $OddChars = @()
    $Chars = $Step2.ToCharArray()
    for ($i = 0; $i -lt $Chars.Length; $i++) {
        if ($i % 2 -eq 0) { $EvenChars += $Chars[$i] }
        else { $OddChars += $Chars[$i] }
    }
    
    # Paso 4: Concatenar arrays
    $Step3 = (-join $EvenChars) + (-join $OddChars)
    
    # Paso 5: Convertir a hexadecimal
    $Bytes = [Text.Encoding]::UTF8.GetBytes($Step3)
    $Step4 = [BitConverter]::ToString($Bytes) -replace '-', ''
    
    # Paso 6: Base64 del hexadecimal
    $Step5 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Step4))
    
    # Paso 7: Convertir de Base64 a ASCII
    $Step6 = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Step5))
    
    # Paso 8: Separar en substrings de 8 caracteres
    $Substrings = @()
    for ($i = 0; $i -lt $Step6.Length; $i += 8) {
        $Substrings += $Step6.Substring($i, [Math]::Min(8, $Step6.Length - $i))
    }
    
    # Paso 9: Dividir por la llave si existe
    if ($Key) {
        $Divided = @()
        foreach ($Sub in $Substrings) {
            try {
                $Num = [int]$Sub
                $Result = $Num / $Key
                $Divided += $Result.ToString()
            } catch {
                $Divided += $Sub
            }
        }
    } else {
        $Divided = $Substrings
    }
    
    # Paso 10: Separar en pares/impares y concatenar con delimitador
    $EvenDivided = @()
    $OddDivided = @()
    for ($i = 0; $i -lt $Divided.Count; $i++) {
        if ($i % 2 -eq 0) { $EvenDivided += $Divided[$i] }
        else { $OddDivided += $Divided[$i] }
    }
    
    $Delimiter = [char](Get-Random -Minimum 65 -Maximum 90)
    $Result = ($EvenDivided -join $Delimiter) + $Delimiter + ($OddDivided -join $Delimiter)
    
    return $Result
}

# Función para descifrar contenido
function Invoke-Decryption {
    param([string]$Content)
    
    Write-Verbose "Decrypting content..."
    
    # Paso 1: Encontrar delimitador
    $Delimiter = $null
    for ($i = 65; $i -le 90; $i++) {
        $char = [char]$i
        if (($Content -split $char).Count -ge 3) {
            $Delimiter = $char
            break
        }
    }
    if (-not $Delimiter) {
        Write-Error "Could not find valid delimiter."
        return $null
    }
    
    # Paso 2: Dividir por delimitador
    $SplitContent = $Content -split $Delimiter | Where-Object { $_ -ne '' }
    
    # Paso 3: Reconstruir substrings
    $MidPoint = [Math]::Ceiling($SplitContent.Count / 2)
    $EvenDivided = $SplitContent[0..($MidPoint - 1)]
    $OddDivided = $SplitContent[$MidPoint..($SplitContent.Count - 1)]
    $Reconstructed = @()
    $MaxLength = [Math]::Max($EvenDivided.Count, $OddDivided.Count)
    for ($i = 0; $i -lt $MaxLength; $i++) {
        if ($i -lt $EvenDivided.Count) { $Reconstructed += $EvenDivided[$i] }
        if ($i -lt $OddDivided.Count) { $Reconstructed += $OddDivided[$i] }
    }
    
    # Paso 4: Multiplicar por la llave
    if ($Key) {
        $Multiplied = @()
        foreach ($Item in $Reconstructed) {
            try {
                $Num = [double]$Item
                $Result = $Num * $Key
                $Multiplied += [math]::Round($Result).ToString()
            } catch {
                $Multiplied += $Item
            }
        }
    } else {
        $Multiplied = $Reconstructed
    }
    
    # Paso 5: Unir substrings
    $Step1 = -join $Multiplied
    
    # Paso 6: Convertir a Base64
    $Step2 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Step1))
    
    # Paso 7: Convertir de Base64 a string
    try {
        $Step3 = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Step2))
    } catch {
        Write-Error "Invalid Base64 string. Decryption failed."
        return $null
    }
    
    # Paso 8: Convertir de hexadecimal a string
    try {
        $Bytes = @()
        for ($i = 0; $i -lt $Step3.Length; $i += 2) {
            $Bytes += [Convert]::ToByte($Step3.Substring($i, 2), 16)
        }
        $Step4 = [Text.Encoding]::UTF8.GetString($Bytes)
    } catch {
        Write-Error "Invalid hexadecimal string. Decryption failed."
        return $null
    }
    
    # Paso 9: Separar en pares/impares
    $Chars = $Step4.ToCharArray()
    $MidPoint = [Math]::Floor($Chars.Length / 2)
    $EvenChars = $Chars[0..($MidPoint - 1)]
    $OddChars = $Chars[$MidPoint..($Chars.Length - 1)]
    
    # Paso 10: Intercalar arrays
    $Interleaved = @()
    $MaxLength = [Math]::Max($EvenChars.Count, $OddChars.Count)
    for ($i = 0; $i -lt $MaxLength; $i++) {
        if ($i -lt $EvenChars.Count) { $Interleaved += $EvenChars[$i] }
        if ($i -lt $OddChars.Count) { $Interleaved += $OddChars[$i] }
    }
    $Step5 = -join $Interleaved
    
    # Paso 11: Revertir reemplazos de Base64
    $Step6 = $Step5 -replace '!', '+' -replace '-', '/' -replace '\*', '='
    
    # Paso 12: Convertir de Base64
    try {
        $Result = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Step6))
    } catch {
        Write-Error "Invalid Base64 string. Decryption failed."
        return $null
    }
    
    return $Result
}

# Función para procesar un archivo individual
function Process-File {
    param(
        [string]$FilePath,
        [string]$Operation # 'Encrypt' o 'Decrypt'
    )
    
    try {
        $Content = Get-Content -Path $FilePath -Raw -ErrorAction Stop
        
        if ([string]::IsNullOrWhiteSpace($Content)) {
            Write-Warning "Skipping empty file: $FilePath"
            return $false
        }
        
        if ($Operation -eq 'Encrypt') {
            $Result = Invoke-Encryption -Content $Content
            if ($Result) {
                $OutputPath = $FilePath + $Extension
                Set-Content -Path $OutputPath -Value $Result -NoNewline
                Write-Host "Encrypted: $([System.IO.Path]::GetFileName($FilePath))" -ForegroundColor Green
                return $true
            }
        } else {
            $Result = Invoke-Decryption -Content $Content
            if ($Result) {
                $OutputPath = $FilePath -replace "$Extension$", ""
                if ($OutputPath -eq $FilePath) {
                    $OutputPath = $FilePath + ".decrypted"
                }
                Set-Content -Path $OutputPath -Value $Result -NoNewline
                Write-Host "Decrypted: $([System.IO.Path]::GetFileName($FilePath))" -ForegroundColor Green
                return $true
            }
        }
    } catch {
        Write-Error "Error processing file '$([System.IO.Path]::GetFileName($FilePath))': $_"
        return $false
    }
    return $false
}

# Función para procesar una carpeta
function Process-Folder {
    param(
        [string]$FolderPath,
        [string]$Operation # 'Encrypt' o 'Decrypt'
    )
    
    # Obtener archivos
    $GetParams = @{
        Path = $FolderPath
        File = $true
    }
    if ($Recursive) {
        $GetParams.Recurse = $true
    }
    
    $Files = Get-ChildItem @GetParams
    
    if ($Files.Count -eq 0) {
        Write-Warning "No files found in folder: $FolderPath"
        return
    }
    
    Write-Host "Processing $($Files.Count) files..." -ForegroundColor Yellow
    
    $SuccessCount = 0
    $ErrorCount = 0
    
    foreach ($File in $Files) {
        Write-Verbose "Processing: $($File.FullName)"
        
        if (Process-File -FilePath $File.FullName -Operation $Operation) {
            $SuccessCount++
        } else {
            $ErrorCount++
        }
    }
    
    Write-Host "Complete. Success: $SuccessCount, Errors: $ErrorCount" -ForegroundColor Cyan
}

# --- Main execution ---
Write-Host "=== Fucky64 Encryption/Decryption Tool ===" -ForegroundColor Cyan

# Verificar si es archivo o carpeta
$IsFile = Test-Path -Path $Path -PathType Leaf
$IsFolder = Test-Path -Path $Path -PathType Container

if ($IsFile) {
    # Procesar archivo individual
    if ($Encrypt) {
        Write-Host "Encrypting file: $Path" -ForegroundColor Yellow
        Process-File -FilePath $Path -Operation 'Encrypt'
    } elseif ($Decrypt) {
        Write-Host "Decrypting file: $Path" -ForegroundColor Yellow
        Process-File -FilePath $Path -Operation 'Decrypt'
    }
} elseif ($IsFolder) {
    # Procesar carpeta
    if ($Encrypt) {
        Write-Host "Encrypting folder: $Path" -ForegroundColor Yellow
        if ($Recursive) { Write-Host "Recursive mode enabled" -ForegroundColor Yellow }
        Process-Folder -FolderPath $Path -Operation 'Encrypt'
    } elseif ($Decrypt) {
        Write-Host "Decrypting folder: $Path" -ForegroundColor Yellow
        if ($Recursive) { Write-Host "Recursive mode enabled" -ForegroundColor Yellow }
        Process-Folder -FolderPath $Path -Operation 'Decrypt'
    }
} else {
    Write-Error "Invalid path: $Path"
    exit 1
}

Write-Host "Operation completed." -ForegroundColor Cyan