<#
.SYNOPSIS
    Decrypts ChaCha20 encrypted files from a folder using BouncyCastle.
.DESCRIPTION
    This script decrypts all .encrypted files in the specified folder using ChaCha20
    with the same password used for encryption.
    Encrypted files are deleted after successful decryption.
.PARAMETER FolderPath
    The path to the folder containing encrypted files.
.PARAMETER Password
    The password used for decryption.
.PARAMETER InputExtension
    The extension of encrypted files (default: .encrypted).
.EXAMPLE
    .\Decrypt-ChaCha20.ps1 -FolderPath "C:\Documents" -Password "SecurePass123"
.EXAMPLE
    .\Decrypt-ChaCha20.ps1 -FolderPath "C:\Documents" -Password "SecurePass123" -InputExtension ".chacha20"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Path to the folder containing encrypted files")]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string]$FolderPath,
    
    [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Password for decryption")]
    [string]$Password,
    
    [Parameter(Mandatory = $false, Position = 2)]
    [string]$InputExtension = ".encrypted"
);

# Load BouncyCastle DLL
Add-Type -Path "BouncyCastle.Cryptography.dll" -ErrorAction Stop;

function Decrypt-File {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $true)]
        [string]$Password,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    );
    
    try {
        # Read encrypted file
        $encryptedBytes = [System.IO.File]::ReadAllBytes($FilePath);
        
        # Check if file is valid (minimum size: salt 16 + iv 8 + at least 1 byte of data)
        if ($encryptedBytes.Length -lt 25) {
            throw "File is too small or corrupted";
        }
        
        # Extract salt (first 16 bytes)
        $salt = New-Object byte[] 16;
        [Array]::Copy($encryptedBytes, 0, $salt, 0, 16);
        
        # Extract IV (next 8 bytes)
        $iv = New-Object byte[] 8;
        [Array]::Copy($encryptedBytes, 16, $iv, 0, 8);
        
        # Extract encrypted data (remaining bytes)
        $cipherDataLength = $encryptedBytes.Length - 24;
        $cipherData = New-Object byte[] $cipherDataLength;
        [Array]::Copy($encryptedBytes, 24, $cipherData, 0, $cipherDataLength);
        
        # Derive key using same salt
        $deriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 100000);
        $keyBytes = $deriveBytes.GetBytes(32);
        
        # Create ChaCha20 engine
        $chacha = New-Object Org.BouncyCastle.Crypto.Engines.ChaChaEngine;
        
        # Create key parameter
        $keyParam = [Org.BouncyCastle.Crypto.Parameters.KeyParameter]::new($keyBytes);
        
        # Create parameters with IV
        $paramWithIV = [Org.BouncyCastle.Crypto.Parameters.ParametersWithIV]::new($keyParam, $iv);
        
        # Initialize for decryption (false = decryption)
        $chacha.Init($false, $paramWithIV);
        
        # Decrypt the data
        $decryptedData = New-Object byte[] $cipherData.Length;
        $chacha.ProcessBytes($cipherData, 0, $cipherData.Length, $decryptedData, 0);
        
        # Write decrypted file
        [System.IO.File]::WriteAllBytes($OutputPath, $decryptedData);
        
        # Delete encrypted file
        [System.IO.File]::Delete($FilePath);
        
        Write-Host "  [OK] Decrypted and removed encrypted: $([System.IO.Path]::GetFileName($FilePath))" -ForegroundColor Green;
        return $true;
    }
    catch {
        Write-Error "  [FAIL] Failed to decrypt $([System.IO.Path]::GetFileName($FilePath)): $_";
        return $false;
    }
}

# Script execution starts here
Write-Host "";
Write-Host "============================================================" -ForegroundColor Cyan;
Write-Host "         CHACHA20 FILE DECRYPTION PROCESS                   " -ForegroundColor Cyan;
Write-Host "============================================================" -ForegroundColor Cyan;
Write-Host "";

# Validate folder exists
if (-not (Test-Path $FolderPath)) {
    Write-Error "Folder not found: $FolderPath";
    exit 1;
}

# Find encrypted files
$encryptedFiles = Get-ChildItem -Path $FolderPath -Filter "*$InputExtension";

if ($encryptedFiles.Count -eq 0) {
    Write-Host "  [WARN] No encrypted files found in $FolderPath" -ForegroundColor Yellow;
    exit 0;
}

Write-Host "  [INFO] Processing $($encryptedFiles.Count) file(s)..." -ForegroundColor White;
Write-Host "  [WARNING] Encrypted files will be DELETED after decryption!" -ForegroundColor Red;
Write-Host "";

# Initialize counters
$successCount = 0;
$failCount = 0;
$startTime = Get-Date;

# Process each file
foreach ($file in $encryptedFiles) {
    # Remove extension to get original filename
    $originalName = $file.Name -replace $InputExtension, '';
    $outputFile = Join-Path $FolderPath $originalName;
    
    if (Decrypt-File -FilePath $file.FullName -Password $Password -OutputPath $outputFile) {
        $successCount++;
    } else {
        $failCount++;
    }
}

$endTime = Get-Date;
$elapsed = $endTime - $startTime;

# Display summary
Write-Host "";
Write-Host "============================================================" -ForegroundColor Cyan;
Write-Host "                   DECRYPTION SUMMARY                       " -ForegroundColor Cyan;
Write-Host "============================================================" -ForegroundColor Cyan;
Write-Host "Total files processed    : $($encryptedFiles.Count)" -ForegroundColor White;
Write-Host "Successfully decrypted   : $successCount" -ForegroundColor Green;
Write-Host "Failed to decrypt        : $failCount" -ForegroundColor Red;
Write-Host "Time elapsed             : $($elapsed.ToString('hh\:mm\:ss'))" -ForegroundColor Yellow;
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan;
Write-Host "Location                  : $FolderPath" -ForegroundColor Yellow;
Write-Host "============================================================" -ForegroundColor Cyan;
Write-Host "";