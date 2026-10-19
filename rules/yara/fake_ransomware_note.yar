rule fake_ransomware_note
{
    meta:
        description = "Detects ransom-note-style content on disk (filenames/content), a common IR triage signal"
        author = "NIDR platform (demo)"
        severity = "critical"

    strings:
        $s1 = "FILES HAVE BEEN ENCRYPTED" nocase
        $s2 = "payment address" nocase
        $s3 = "price doubles" nocase
        $s4 = "do not attempt to decrypt" nocase

    condition:
        2 of them
}
