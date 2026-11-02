rule win_astaroth_delivery_lnk_102026 {
  meta:
    author = "0x0d4y"
    description = "Detects the Astaroth delivery LNK that copies scrobj.dll to an ADS and invokes a remote scriptlet"
    date = "2026-10-18"
    score = 90
    malware_family = "win.astaroth"
    component = "delivery_lnk"
    sample_sha256 = "454339578b870730d146ad8fec776a9d59360417ab1c2e0e5f88414baf92a13d"
    license = "CC BY 4.0"

  strings:
    $cmd_shell = "Windows\\SyStem32\\CMd.exe" ascii wide nocase
    $cmd_ads = "*crObJ.* > %temp%\\n1LUQ7.log:h6JSb" ascii wide nocase
    $cmd_regsvr = "/i:!_p!://" ascii wide nocase
    $cmd_switches = "/u /s %temp%\\\\n1LUQ7.log:h6JSb" ascii wide nocase
    $host = "plosancol.aguamammillaria.cfd" ascii wide nocase

  condition:
    uint32(0) == 0x0000004c and
    filesize < 32KB and
    3 of them
}
