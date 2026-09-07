<#
.SYNOPSIS
    Encrypts or decrypts files in a path using 256-bit Rijndael (AES).
.DESCRIPTION
    Recursively processes all files in the specified path.
    Files are overwritten with their encrypted/decrypted version and the ".rijndael" extension is added.
.PARAMETER Path
    Directory path to process.
.PARAMETER Operation
    "Encrypt" or "Decrypt".
.PARAMETER Password
    Password to derive the 256-bit key.
.PARAMETER Salt
    Salt for key derivation (optional, randomly generated if not provided).
    If provided, must be in Base64 format.
.EXAMPLE
    .\RijndaelCrypto.ps1 -Path "C:\Users\Public\RansomTest" -Operation Encrypt -Password "MySecurePassword123"
.EXAMPLE
    .\RijndaelCrypto.ps1 -Path "C:\Users\Public\RansomTest" -Operation Decrypt -Password "MySecurePassword123"
#>

[CmdletBinding()]
param(
    # Mandatory path parameter
    [Parameter(Mandatory = $true)]
    [string]$Path,

    # Mandatory operation with restricted values
    [Parameter(Mandatory = $true)]
    [ValidateSet("Encrypt", "Decrypt")]
    [string]$Operation,

    # Mandatory password for key derivation
    [Parameter(Mandatory = $true)]
    [string]$Password,

    # Optional Base64 salt
    [string]$Salt = ""
)

<#
    Function: Get-KeyAndIV
    Purpose: Derives 256-bit key and 128-bit IV using PBKDF2 (Rfc2898DeriveBytes)
    Parameters:
        - Password: User password
        - Salt: Base64 encoded salt (optional)
    Returns: Hashtable with Key, IV, and Salt
#>
function Get-KeyAndIV {
    param(
        [string]$Password,
        [string]$Salt
    )
    
    # Generate salt if not provided
    if ([string]::IsNullOrWhiteSpace($Salt)) {
        # Create 8-byte salt (64-bit) - WARNING: Should be 16 bytes for better security
        $saltBytes = New-Object byte[] 8
        # Use cryptographic random number generator
        $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
        $rng.GetBytes($saltBytes)
        $rng.Dispose()
        # Convert to Base64
        $Salt = [Convert]::ToBase64String($saltBytes)
        # WARNING: Displaying salt on screen is a security risk
        Write-Host "[INFO] Salt generated (SAVE IT): $Salt" -ForegroundColor Yellow
        $saltBytes = [Convert]::FromBase64String($Salt)
    } else {
        # Validate provided salt is valid Base64
        try {
            $saltBytes = [Convert]::FromBase64String($Salt)
            Write-Host "[INFO] Using provided Salt: $Salt" -ForegroundColor Cyan
        } catch {
            Write-Error "Provided Salt is not valid Base64: $Salt"
            Write-Host "Example of valid Salt: '7Qm87C9P2rA='" -ForegroundColor Yellow
            throw "Invalid Salt"
        }
    }
    
    # Derive key and IV using PBKDF2
    # WARNING: 10000 iterations is low for current standards (recommended 600000+)
    $iterations = 10000
    $deriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $saltBytes, $iterations)
    
    # 32 bytes for key (256-bit) + 16 bytes for IV (128-bit)
    $keyBytes = $deriveBytes.GetBytes(32)  # 256-bit key
    $ivBytes = $deriveBytes.GetBytes(16)   # 128-bit IV
    
    $deriveBytes.Dispose()
    
    return @{
        Key = $keyBytes
        IV = $ivBytes
        Salt = $Salt
    }
}

<#
    Function: Encrypt-File
    Purpose: Encrypts a single file using AES-256 in CBC mode
    Parameters:
        - FilePath: Full path of the file to encrypt
        - Key: 256-bit key as byte array
        - IV: 128-bit initialization vector as byte array
    Returns: $true if encryption succeeded, $false otherwise
    Note: Original file is deleted and replaced with encrypted version (.rijndael)
#>
function Encrypt-File {
    param(
        [string]$FilePath,
        [byte[]]$Key,
        [byte[]]$IV
    )
    
    try {
        # WARNING: Loads entire file into memory - Risk for large files
        $plainBytes = [System.IO.File]::ReadAllBytes($FilePath)
        
        # Create Rijndael (AES) instance
        $rijndael = [System.Security.Cryptography.RijndaelManaged]::Create()
        $rijndael.Key = $Key
        $rijndael.IV = $IV
        $rijndael.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $rijndael.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        
        # Create encryptor
        $encryptor = $rijndael.CreateEncryptor()
        # WARNING: Encrypts entire block at once - Not recommended for large files
        $cipherBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
        
        $rijndael.Dispose()
        
        # Write encrypted file to temporary file
        $tempFile = $FilePath + ".tmp"
        [System.IO.File]::WriteAllBytes($tempFile, $cipherBytes)
        
        # Delete original and rename temp to .rijndael
        Remove-Item $FilePath -Force
        Rename-Item $tempFile -NewName ($FilePath + ".rijndael") -ErrorAction Stop
        
        return $true
    } catch {
        Write-Error "Error encrypting '$FilePath': $_"
        return $false
    }
}

<#
    Function: Decrypt-File
    Purpose: Decrypts a .rijndael file using AES-256 in CBC mode
    Parameters:
        - FilePath: Full path of the .rijndael file to decrypt
        - Key: 256-bit key as byte array
        - IV: 128-bit initialization vector as byte array
    Returns: $true if decryption succeeded, $false otherwise
    Note: Encrypted file is deleted and replaced with decrypted original
#>
function Decrypt-File {
    param(
        [string]$FilePath,
        [byte[]]$Key,
        [byte[]]$IV
    )
    
    try {
        # WARNING: Loads entire file into memory
        $cipherBytes = [System.IO.File]::ReadAllBytes($FilePath)
        
        # Create Rijndael (AES) instance
        $rijndael = [System.Security.Cryptography.RijndaelManaged]::Create()
        $rijndael.Key = $Key
        $rijndael.IV = $IV
        $rijndael.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $rijndael.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        
        # Create decryptor
        $decryptor = $rijndael.CreateDecryptor()
        # WARNING: Decrypts entire block at once
        $plainBytes = $decryptor.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length)
        
        $rijndael.Dispose()
        
        # Determine original filename (remove .rijndael extension)
        $newName = $FilePath -replace '\.rijndael$', ''
        $tempFile = $FilePath + ".tmp"
        [System.IO.File]::WriteAllBytes($tempFile, $plainBytes)
        
        # Delete encrypted file and rename temp to original
        Remove-Item $FilePath -Force
        Rename-Item $tempFile -NewName $newName -ErrorAction Stop
        
        return $true
    } catch {
        Write-Error "Error decrypting '$FilePath': $_"
        return $false
    }
}

# =============================================================================
# UI FUNCTIONS
# =============================================================================

<#
    Function: Write-Banner
    Purpose: Displays the initial script banner
#>
function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   RIJNDAEL CRYPTO - AES 256-bit (In-Place Processing)" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "   Rijndael CBC Mode | PBKDF2 Key Derivation" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

<#
    Function: Write-Info
    Purpose: Displays formatted information in two columns
    Parameters:
        - Label: Information label
        - Value: Information value
        - Color: Color of the value (default White)
#>
function Write-Info {
    param([string]$Label, [string]$Value, [string]$Color = "White")
    Write-Host ("  {0,-18} : " -f $Label) -NoNewline -ForegroundColor DarkGray
    Write-Host $Value -ForegroundColor $Color
}

<#
    Function: Write-Separator
    Purpose: Displays a separator line
#>
function Write-Separator {
    Write-Host ("  " + "-" * 58) -ForegroundColor DarkGray
}

<#
    Function: Write-Success
    Purpose: Displays success message in green
#>
function Write-Success {
    param([string]$Message)
    Write-Host ("  [OK] " + $Message) -ForegroundColor Green
}

<#
    Function: Write-ErrorMsg
    Purpose: Displays error message in red
#>
function Write-ErrorMsg {
    param([string]$Message)
    Write-Host ("  [FAIL] " + $Message) -ForegroundColor Red
}

<#
    Function: Write-WarningMsg
    Purpose: Displays warning message in yellow
#>
function Write-WarningMsg {
    param([string]$Message)
    Write-Host ("  [WARN] " + $Message) -ForegroundColor Yellow
}

<#
    Function: Write-ProgressBar
    Purpose: Displays a progress bar updated in real-time
    Parameters:
        - Current: Current number of processed files
        - Total: Total files to process
        - FileName: Current filename (truncated if too long)
#>
function Write-ProgressBar {
    param([int]$Current, [int]$Total, [string]$FileName)
    # Calculate completion percentage
    $percent = [math]::Round(($Current / $Total) * 100, 0)
    $barLength = 35
    # Calculate filled and empty characters
    $filled = [math]::Round(($percent / 100) * $barLength)
    $empty = $barLength - $filled
    # Build visual bar
    $bar = ("#" * $filled) + ("." * $empty)
    $pct = $percent.ToString("00")
    # Display on same line (using `r` to overwrite)
    Write-Host ("`r  [{0}] {1}%  {2}" -f $bar, $pct, $FileName) -NoNewline -ForegroundColor Cyan
}

# =============================================================================
# MAIN PROCESSING FUNCTION
# =============================================================================

<#
    Function: Process-Directory
    Purpose: Main orchestration function for encrypt/decrypt process
    Flow:
        1. Displays configuration information
        2. Derives key and IV
        3. Gets list of files to process
        4. Processes each file with progress display
        5. Shows final statistics
#>
function Process-Directory {
    Write-Separator
    Write-Info -Label "Target Path" -Value $Path -Color "White"
    Write-Info -Label "Operation" -Value $Operation -Color $(if ($Operation -eq "Encrypt") { "Yellow" } else { "Magenta" })
    Write-Info -Label "Password" -Value $("•" * $Password.Length) -Color "DarkGray"
    
    # Derive key and IV
    Write-Host ""
    Write-Info -Label "Deriving Key" -Value "PBKDF2 (10000 iterations)" -Color "Cyan"
    
    try {
        $keyIv = Get-KeyAndIV -Password $Password -Salt $Salt
    } catch {
        Write-ErrorMsg -Message "Error deriving key: $_"
        return
    }
    
    # Extract values from hashtable
    $Key = $keyIv.Key
    $IV = $keyIv.IV
    $Salt = $keyIv.Salt
    
    # Display derived key information
    Write-Info -Label "Salt" -Value $Salt -Color "DarkGray"
    Write-Info -Label "Key Size" -Value "256 bits" -Color "Green"
    Write-Info -Label "IV Size" -Value "128 bits" -Color "Green"
    Write-Separator
    Write-Host ""
    
    # Validate path exists
    if (-not (Test-Path $Path)) {
        Write-ErrorMsg -Message "Path does not exist: $Path"
        return
    }
    
    # Get files based on operation
    if ($Operation -eq "Encrypt") {
        # For encrypt: all files WITHOUT .rijndael extension
        $files = Get-ChildItem -Path $Path -Recurse -File | Where-Object { -not $_.Name.EndsWith(".rijndael") }
        $action = "Encrypting"
    } else {
        # For decrypt: only files with .rijndael extension
        $files = Get-ChildItem -Path $Path -Recurse -File -Filter "*.rijndael"
        $action = "Decrypting"
    }
    
    $total = $files.Count
    
    # Check if there are files to process
    if ($total -eq 0) {
        Write-WarningMsg -Message "No files found to process"
        return
    }
    
    Write-Info -Label "Files Found" -Value $total.ToString() -Color "Cyan"
    Write-Info -Label "Mode" -Value "In-Place (originals deleted)" -Color "Yellow"
    Write-Host ""
    
    # Initialize counters for statistics
    $processed = 0
    $success = 0
    $failed = 0
    $failedFiles = @()  # List to store failed filenames
    
    # Process each file
    foreach ($file in $files) {
        $processed++
        # Truncate filename if too long for progress bar
        $fileName = $file.Name
        if ($fileName.Length -gt 30) { $fileName = $fileName.Substring(0, 27) + "..." }
        
        # Update progress bar
        Write-ProgressBar -Current $processed -Total $total -FileName $fileName
        
        # Execute operation accordingly
        if ($Operation -eq "Encrypt") {
            $result = Encrypt-File -FilePath $file.FullName -Key $Key -IV $IV
        } else {
            $result = Decrypt-File -FilePath $file.FullName -Key $Key -IV $IV
        }
        
        # Update statistics
        if ($result) {
            $success++
        } else {
            $failed++
            $failedFiles += $file.Name
        }
    }
    
    # Clear progress line and show final statistics
    Write-Host ""
    Write-Host ""
    Write-Separator
    Write-Host ""
    
    # Display results
    Write-Success -Message ("Processed: {0} files" -f $total)
    Write-Success -Message ("Success: {0}" -f $success)
    
    # Show failed files if any
    if ($failed -gt 0) {
        Write-ErrorMsg -Message ("Failed: {0}" -f $failed)
        Write-Host ""
        Write-WarningMsg -Message "Failed files:"
        foreach ($f in $failedFiles) {
            Write-Host ("    - " + $f) -ForegroundColor Red
        }
    } else {
        Write-Success -Message "All files processed successfully"
    }
    
    Write-Host ""
    Write-Info -Label "Location" -Value $Path -Color "Cyan"
    Write-Separator
}

# =============================================================================
# SCRIPT ENTRY POINT - EXECUTION
# =============================================================================

# Display banner
Write-Banner
Write-Separator
# Execute main process
Process-Directory
Write-Host ""