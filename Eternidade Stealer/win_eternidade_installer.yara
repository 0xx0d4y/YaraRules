rule win_eternidade_installer_102026 {
  meta:
    author = "0x0d4y"
    description = "Detects the malicious Eternidade MSI bundle and its custom installation layout"
    reference = "https://0x0d4y.blog/inside-brazils-financial-malware-ecosystem-deep-dive-into-eternidade-stealer/"
    date = "2026-10-18"
    score = 95
    malware_family = "win.eternidade"
    component = "msi_installer"
    sample_sha256 = "b78ebc306f33c9eec1270310a834b4076f4c77c2683c7f4a9fd63d330f70e224"
    license = "CC BY 4.0"

  strings:
    $dir = "2IFtuO7AL7Ow" ascii wide
    $run_value = "CINF415qv6" ascii wide
    $loader = "taskhost_sys.exe" ascii wide nocase
    $wrapper = "csrss_svc.log" ascii wide nocase
    $ota = "s_v2.ota" ascii wide nocase
    $dkd = "s_v2.dkd" ascii wide nocase
    $launch = "\"[INSTALLFOLDER]csrss_svc.log\"" ascii wide nocase

  condition:
    uint32(0) == 0xe011cfd0 and uint32(4) == 0xe11ab1a1 and
    filesize > 10MB and
    5 of them
}
