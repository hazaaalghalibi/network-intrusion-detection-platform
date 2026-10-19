rule eicar_test_string
{
    meta:
        description = "Matches the industry-standard EICAR AV test string"
        author = "NIDR platform (demo)"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
        severity = "low"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}
