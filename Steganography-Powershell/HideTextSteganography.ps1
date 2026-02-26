function Hide-Text {
    param(
        [string]$ImagePath,
        [string]$Message,
        [string]$ImageOutput
    )
    
    if([string]::IsNullOrEmpty($ImagePath) -or [string]::IsNullOrEmpty($Message) -or [string]::IsNullOrEmpty($ImageOutput)){
        Write-Output ">> All arguments were not specified <<";
        Write-Output "* ImagePath [string] --> Path to original image";
        Write-Output "* Message [string] --> Message to hide";
        Write-Output "* ImageOutput [string] --> Path to image with message hidden";
        return;
    }

    if ($ImagePath -match '\.jpg$|\.jpeg$') {
        Write-Output "JPEG/JPG is not supported. Input must be PNG";
        return;
    }

    if ($ImageOutput -match '\.jpg$|\.jpeg$') {
        Write-Warning "JPEG/JPG is not supported. Changing output to PNG...";
        $ImageOutput = $ImageOutput -replace '\.jpg$|\.jpeg$', '.png';
        return;
    }

    Add-Type -AssemblyName System.Drawing;
    
    $imagen = [System.Drawing.Image]::FromFile($ImagePath);
    $bitmap = New-Object System.Drawing.Bitmap($imagen);
    
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Message + "`0");
    $indiceByte = 0;
    $bitActual = 0;
    
    for ($y = 0; $y -lt $bitmap.Height; $y++) {
        for ($x = 0; $x -lt $bitmap.Width; $x++) {
            if ($indiceByte -ge $bytes.Length) { break }
            
            $pixel = $bitmap.GetPixel($x, $y);
            
            $bitValor = ($bytes[$indiceByte] -shr $bitActual) -band 1;
            $nuevoAzul = ($pixel.B -band 0xFE) -bor $bitValor;
            
            $nuevoPixel = [System.Drawing.Color]::FromArgb($pixel.A, $pixel.R, $pixel.G, $nuevoAzul);
            $bitmap.SetPixel($x, $y, $nuevoPixel);
            
            $bitActual++;
            if ($bitActual -ge 8) {
                $bitActual = 0;
                $indiceByte++;
            }
        }
    }
    
    $bitmap.Save($ImageOutput, [System.Drawing.Imaging.ImageFormat]::Png);
    $imagen.Dispose();
    $bitmap.Dispose();
    
    Write-Host "Message hidden in: $ImageOutput";
}

