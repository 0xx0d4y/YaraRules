rule win_astaroth_persistence_lnk_102026 {
  meta:
    author = "0x0d4y"
    description = "Detects the Astaroth PLAX startup LNK that launches the AutoIt execution layer"
    date = "2026-10-18"
    score = 85
    malware_family = "win.astaroth"
    component = "startup_lnk"
    sample_sha256 = "32e5b7089317f4167b429606f5418b9e53a8278f2f89fa767edffe8056c9d70b"
    license = "CC BY 4.0"

  strings:
    $ps = "WindowsPowerShell\\v1.0\\powershell.exe" ascii wide nocase
    $hidden = "-windowstyle hidden -Command" ascii wide nocase
    $cache = "Users\\Public" ascii wide nocase

  condition:
    uint32(0) == 0x0000004c and
    filesize < 32KB and
    all of them
}
