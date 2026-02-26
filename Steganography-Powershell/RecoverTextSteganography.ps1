function Get-Text {
    param([string]$ImagePath)
    
    if([string]::IsNullOrEmpty($ImagePath)){
        Write-Output ">> All arguments were not specified <<";
        Write-Output "* ImagePath [string] --> Path to original image";
        return;
    }


    Add-Type -AssemblyName System.Drawing;
    
    $bitmap = [System.Drawing.Bitmap]::FromFile($ImagePath);
    $bytes = New-Object System.Collections.ArrayList;
    $byteActual = 0;
    $bitActual = 0;
    
    for ($y = 0; $y -lt $bitmap.Height; $y++) {
        for ($x = 0; $x -lt $bitmap.Width; $x++) {
            $pixel = $bitmap.GetPixel($x, $y);
            $bit = $pixel.B -band 1;
            $byteActual = $byteActual -bor ($bit -shl $bitActual);
            
            $bitActual++;
            if ($bitActual -ge 8) {
                if ($byteActual -eq 0) { break }
                [void]$bytes.Add($byteActual);
                $byteActual = 0;
                $bitActual = 0;
            }
        }
    }
    
    $bitmap.Dispose();
    
    return [System.Text.Encoding]::UTF8.GetString($bytes);
}