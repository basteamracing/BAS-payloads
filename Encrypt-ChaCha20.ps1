<#
.SYNOPSIS
    Encrypts all files in a folder using ChaCha20 algorithm with BouncyCastle.
.DESCRIPTION
    This script encrypts all files in the specified folder using ChaCha20 encryption
    with PBKDF2 key derivation and random salt/nonce per file.
    Original files are deleted after successful encryption.
.PARAMETER FolderPath
    The path to the folder containing files to encrypt.
.PARAMETER Password
    The password used for encryption.
.PARAMETER OutputExtension
    The extension to add to encrypted files (default: .encrypted).
.EXAMPLE
    .\Encrypt-ChaCha20.ps1 -FolderPath "C:\Documents" -Password "SecurePass123"
.EXAMPLE
    .\Encrypt-ChaCha20.ps1 -FolderPath "C:\Documents" -Password "SecurePass123" -OutputExtension ".chacha20"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Path to the folder containing files to encrypt")]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string]$FolderPath,
    
    [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Password for encryption")]
    [string]$Password,
    
    [Parameter(Mandatory = $false, Position = 2)]
    [string]$OutputExtension = ".encrypted"
);

# Load BouncyCastle DLL
Add-Type -Path "BouncyCastle.Cryptography.dll" -ErrorAction Stop;

function Encrypt-File {
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
        # Read file as bytes
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath);
        
        # Generate random salt (16 bytes)
        $salt = New-Object byte[] 16;
        $rng.GetBytes($salt);
        
        # Derive key using PBKDF2 (100,000 iterations)
        $deriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 100000);
        $keyBytes = $deriveBytes.GetBytes(32);
        
        # Generate random IV (8 bytes for ChaCha20 in BouncyCastle)
        $iv = New-Object byte[] 8;
        $rng.GetBytes($iv);
        
        # Create ChaCha20 engine
        $chacha = New-Object Org.BouncyCastle.Crypto.Engines.ChaChaEngine;
        
        # Create key parameter
        $keyParam = [Org.BouncyCastle.Crypto.Parameters.KeyParameter]::new($keyBytes);
        
        # Create parameters with IV
        $paramWithIV = [Org.BouncyCastle.Crypto.Parameters.ParametersWithIV]::new($keyParam, $iv);
        
        # Initialize for encryption (true = encryption)
        $chacha.Init($true, $paramWithIV);
        
        # Encrypt the data
        $encryptedData = New-Object byte[] $fileBytes.Length;
        $chacha.ProcessBytes($fileBytes, 0, $fileBytes.Length, $encryptedData, 0);
        
        # Build output: salt (16) + iv (8) + encrypted data
        $outputBytes = New-Object byte[] (24 + $encryptedData.Length);
        [Array]::Copy($salt, 0, $outputBytes, 0, 16);
        [Array]::Copy($iv, 0, $outputBytes, 16, 8);
        [Array]::Copy($encryptedData, 0, $outputBytes, 24, $encryptedData.Length);
        
        # Write encrypted file
        [System.IO.File]::WriteAllBytes($OutputPath, $outputBytes);
        
        # Delete original file
        [System.IO.File]::Delete($FilePath);
        
        Write-Host "  [OK] Encrypted: $([System.IO.Path]::GetFileName($FilePath))" -ForegroundColor Green;
        return $true;
    }
    catch {
        Write-Error "  [FAIL] Failed to encrypt $([System.IO.Path]::GetFileName($FilePath)): $_";
        return $false;
    }
}

# Script execution starts here
Write-Host "";
Write-Host "============================================================" -ForegroundColor Cyan;
Write-Host "         CHACHA20 FILE ENCRYPTION PROCESS                   " -ForegroundColor Cyan;
Write-Host "============================================================" -ForegroundColor Cyan;
Write-Host "";

# Validate folder exists
if (-not (Test-Path $FolderPath)) {
    Write-Error "Folder not found: $FolderPath";
    exit 1;
}

# Initialize RNG once (global)
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider;

# Get all files (excluding directories)
$files = Get-ChildItem -Path $FolderPath -File;

# Filter out already encrypted files
$files = $files | Where-Object { -not $_.Name.EndsWith($OutputExtension) };

if ($files.Count -eq 0) {
    Write-Host "  [WARN] No files found to encrypt in $FolderPath" -ForegroundColor Yellow;
    exit 0;
}

Write-Host "  [INFO] Processing $($files.Count) file(s)..." -ForegroundColor White;
Write-Host "  [WARNING] Original files will be DELETED after encryption!" -ForegroundColor Red;
Write-Host "";

# Initialize counters
$successCount = 0;
$failCount = 0;
$startTime = Get-Date;
$processedFiles = 0;

# Process each file
foreach ($file in $files) {
    $processedFiles++;
    $outputFile = Join-Path $FolderPath ($file.Name + $OutputExtension);
    
    # Show progress every 10 files
    if ($processedFiles % 10 -eq 0) {
        Write-Host "  [PROGRESS] $processedFiles / $($files.Count) files processed..." -ForegroundColor Yellow;
    }
    
    if (Encrypt-File -FilePath $file.FullName -Password $Password -OutputPath $outputFile) {
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
Write-Host "                   ENCRYPTION SUMMARY                       " -ForegroundColor Cyan;
Write-Host "============================================================" -ForegroundColor Cyan;
Write-Host "Total files processed    : $($files.Count)" -ForegroundColor White;
Write-Host "Successfully encrypted   : $successCount" -ForegroundColor Green;
Write-Host "Failed to encrypt        : $failCount" -ForegroundColor Red;
Write-Host "Time elapsed             : $($elapsed.ToString('hh\:mm\:ss'))" -ForegroundColor Yellow;
Write-Host "------------------------------------------------------------" -ForegroundColor Cyan;
Write-Host "Location                  : $FolderPath" -ForegroundColor Yellow;
Write-Host "============================================================" -ForegroundColor Cyan;
Write-Host "";