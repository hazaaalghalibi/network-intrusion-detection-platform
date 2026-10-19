rule suspicious_powershell_cradle
{
    meta:
        description = "Detects PowerShell download-cradle strings often used by malware droppers"
        author = "NIDR platform (demo)"
        severity = "high"

    strings:
        $cradle1 = "DownloadString(" nocase
        $cradle2 = "IEX (New-Object" nocase
        $encoded = "-EncodedCommand" nocase
        $hidden  = "-WindowStyle Hidden" nocase

    condition:
        2 of them
}
