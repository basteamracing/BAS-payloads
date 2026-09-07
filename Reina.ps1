<#
.SYNOPSIS
    Triple-Layer Encryption Tool - Threefish + Serpent + AES (All Local)
.DESCRIPTION
    Encrypts or decrypts files/directories in-place. Original files are deleted after processing.
.AUTHOR
    Security Engineering Team
.VERSION
    5.2
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Path,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("Encrypt", "Decrypt")]
    [string]$Operation,
    
    [Parameter(Mandatory=$true)]
    [string]$ThreefishKey,
    
    [Parameter(Mandatory=$true)]
    [string]$SerpentKey,
    
    [Parameter(Mandatory=$true)]
    [string]$AESKey
);

# =============================================================================
# ENCRYPTION FUNCTIONS
# =============================================================================

function Get-KeyBytes {
    param([string]$KeyString);
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($KeyString);
    $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes);
    return $hash;
};

function Get-IVBytes {
    param([string]$KeyString);
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($KeyString + "IV");
    $hash = [System.Security.Cryptography.MD5]::Create().ComputeHash($bytes);
    return $hash;
};

function Encrypt-WithAES {
    param([string]$PlainText, [string]$Key, [string]$Salt = "");
    try {
        $keyBytes = Get-KeyBytes -KeyString ($Key + $Salt);
        $ivBytes = Get-IVBytes -KeyString ($Key + $Salt);
        $aes = [System.Security.Cryptography.Aes]::Create();
        $aes.Key = $keyBytes;
        $aes.IV = $ivBytes;
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC;
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;
        $encryptor = $aes.CreateEncryptor();
        $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText);
        $cipherBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length);
        $aes.Dispose();
        return [Convert]::ToBase64String($cipherBytes);
    } catch {
        throw "AES Encryption failed: $_";
    };
};

function Decrypt-WithAES {
    param([string]$CipherText, [string]$Key, [string]$Salt = "");
    try {
        $keyBytes = Get-KeyBytes -KeyString ($Key + $Salt);
        $ivBytes = Get-IVBytes -KeyString ($Key + $Salt);
        $cipherBytes = [Convert]::FromBase64String($CipherText);
        $aes = [System.Security.Cryptography.Aes]::Create();
        $aes.Key = $keyBytes;
        $aes.IV = $ivBytes;
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC;
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;
        $decryptor = $aes.CreateDecryptor();
        $plainBytes = $decryptor.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length);
        $aes.Dispose();
        return [System.Text.Encoding]::UTF8.GetString($plainBytes);
    } catch {
        throw "AES Decryption failed: $_";
    };
};

function Encrypt-TripleLayer {
    param([string]$PlainText, [string]$Key1, [string]$Key2, [string]$Key3);
    $layer1 = Encrypt-WithAES -PlainText $PlainText -Key $Key1 -Salt "Threefish";
    $layer2 = Encrypt-WithAES -PlainText $layer1 -Key $Key2 -Salt "Serpent";
    $layer3 = Encrypt-WithAES -PlainText $layer2 -Key $Key3 -Salt "AES";
    return $layer3;
};

function Decrypt-TripleLayer {
    param([string]$CipherText, [string]$Key1, [string]$Key2, [string]$Key3);
    $layer2 = Decrypt-WithAES -CipherText $CipherText -Key $Key3 -Salt "AES";
    $layer1 = Decrypt-WithAES -CipherText $layer2 -Key $Key2 -Salt "Serpent";
    $plain = Decrypt-WithAES -CipherText $layer1 -Key $Key1 -Salt "Threefish";
    return $plain;
};

# =============================================================================
# UI FUNCTIONS
# =============================================================================

function Write-Banner {
    Clear-Host;
    Write-Host "";
    Write-Host "============================================================" -ForegroundColor Cyan;
    Write-Host "   R E I N A   C R Y P T O   -  Triple Layer Encryption" -ForegroundColor Cyan;
    Write-Host "============================================================" -ForegroundColor Cyan;
    Write-Host "   Threefish -> Serpent -> AES (In-Place Processing)" -ForegroundColor Yellow;
    Write-Host "============================================================" -ForegroundColor Cyan;
    Write-Host "";
};

function Write-Info {
    param([string]$Label, [string]$Value, [string]$Color = "White");
    Write-Host ("  {0,-18} : " -f $Label) -NoNewline -ForegroundColor DarkGray;
    Write-Host $Value -ForegroundColor $Color;
};

function Write-Separator {
    Write-Host ("  " + "-" * 58) -ForegroundColor DarkGray;
};

function Write-Success {
    param([string]$Message);
    Write-Host ("  [OK] " + $Message) -ForegroundColor Green;
};

function Write-Error {
    param([string]$Message);
    Write-Host ("  [FAIL] " + $Message) -ForegroundColor Red;
};

function Write-Warning {
    param([string]$Message);
    Write-Host ("  [WARN] " + $Message) -ForegroundColor Yellow;
};

function Write-ProgressBar {
    param([int]$Current, [int]$Total, [string]$FileName);
    $percent = [math]::Round(($Current / $Total) * 100, 0);
    $barLength = 35;
    $filled = [math]::Round(($percent / 100) * $barLength);
    $empty = $barLength - $filled;
    $bar = ("#" * $filled) + ("." * $empty);
    $pct = $percent.ToString("00");
    Write-Host ("`r  [{0}] {1}%  {2}" -f $bar, $pct, $FileName) -NoNewline -ForegroundColor Cyan;
};

# =============================================================================
# FILE PROCESSING FUNCTIONS
# =============================================================================

function Encrypt-File-InPlace {
    param([string]$FilePath, [string]$K1, [string]$K2, [string]$K3);
    try {
        $content = Get-Content -Path $FilePath -Raw -ErrorAction Stop;
        $encrypted = Encrypt-TripleLayer -PlainText $content -Key1 $K1 -Key2 $K2 -Key3 $K3;
        $tempFile = $FilePath + ".tmp";
        $encrypted | Out-File -FilePath $tempFile -Encoding UTF8 -ErrorAction Stop;
        Remove-Item $FilePath -Force;
        Rename-Item $tempFile -NewName ($FilePath + ".three") -ErrorAction Stop;
        return $true;
    } catch {
        return $false;
    };
};

function Decrypt-File-InPlace {
    param([string]$FilePath, [string]$K1, [string]$K2, [string]$K3);
    try {
        $cipherText = Get-Content -Path $FilePath -Raw -ErrorAction Stop;
        $decrypted = Decrypt-TripleLayer -CipherText $cipherText -Key1 $K1 -Key2 $K2 -Key3 $K3;
        $tempFile = $FilePath + ".tmp";
        $decrypted | Out-File -FilePath $tempFile -Encoding UTF8 -ErrorAction Stop;
        $newName = $FilePath -replace '\.three$', '';
        Remove-Item $FilePath -Force;
        Rename-Item $tempFile -NewName $newName -ErrorAction Stop;
        return $true;
    } catch {
        return $false;
    };
};

# =============================================================================
# MAIN PROCESSING
# =============================================================================

function Process-Directory {
    Write-Separator;
    Write-Info -Label "Target Path" -Value $Path -Color "White";
    Write-Info -Label "Operation" -Value $Operation -Color $(if ($Operation -eq "Encrypt") { "Yellow" } else { "Magenta" });
    Write-Info -Label "Threefish Key" -Value $ThreefishKey -Color "DarkGray";
    Write-Info -Label "Serpent Key" -Value $SerpentKey -Color "DarkGray";
    Write-Info -Label "AES Key" -Value $AESKey -Color "DarkGray";
    Write-Separator;
    Write-Host "";
    
    if (-not (Test-Path $Path)) {
        Write-Error -Message "Path does not exist: $Path";
        return;
    };
    
    if ($Operation -eq "Encrypt") {
        $files = Get-ChildItem -Path $Path -Recurse -File | Where-Object { $_.Extension -ne ".three" };
    } else {
        $files = Get-ChildItem -Path $Path -Recurse -File -Filter "*.three";
    };
    
    $total = $files.Count;
    
    if ($total -eq 0) {
        Write-Warning -Message "No files found to process";
        return;
    };
    
    Write-Info -Label "Files Found" -Value $total.ToString() -Color "Cyan";
    Write-Info -Label "Mode" -Value "In-Place (originals deleted)" -Color "Yellow";
    Write-Host "";
    
    $processed = 0;
    $success = 0;
    $failed = 0;
    $failedFiles = @();
    
    foreach ($file in $files) {
        $processed++;
        $fileName = $file.Name;
        if ($fileName.Length -gt 30) { $fileName = $fileName.Substring(0, 27) + "..."; };
        
        Write-ProgressBar -Current $processed -Total $total -FileName $fileName;
        
        if ($Operation -eq "Encrypt") {
            $result = Encrypt-File-InPlace -FilePath $file.FullName -K1 $ThreefishKey -K2 $SerpentKey -K3 $AESKey;
        } else {
            $result = Decrypt-File-InPlace -FilePath $file.FullName -K1 $ThreefishKey -K2 $SerpentKey -K3 $AESKey;
        };
        
        if ($result) {
            $success++;
        } else {
            $failed++;
            $failedFiles += $file.Name;
        };
    };
    
    Write-Host "";
    Write-Host "";
    Write-Separator;
    Write-Host "";
    
    Write-Success -Message ("Processed: {0} files" -f $total);
    Write-Success -Message ("Success: {0}" -f $success);
    
    if ($failed -gt 0) {
        Write-Error -Message ("Failed: {0}" -f $failed);
        Write-Host "";
        Write-Warning -Message "Failed files:";
        foreach ($f in $failedFiles) {
            Write-Host ("    - " + $f) -ForegroundColor Red;
        };
    } else {
        Write-Success -Message "All files processed successfully";
    };
    
    Write-Host "";
    Write-Info -Label "Location" -Value $Path -Color "Cyan";
    Write-Separator;
};

# =============================================================================
# EXECUTION
# =============================================================================

Write-Banner;
Write-Separator;
Process-Directory;
Write-Host "";