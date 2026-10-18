import "pe"

rule win_eternidade_ota_loader_102026 {
  meta:
    author = "0x0d4y"
    description = "Detects the decrypted Eternidade native stage that consumes the DKD and hollows RegSvcs"
    reference = "https://0x0d4y.blog/inside-brazils-financial-malware-ecosystem-deep-dive-into-eternidade-stealer/"
    date = "2026-10-18"
    score = 95
    malware_family = "win.eternidade"
    component = "native_hollowing_loader"
    sample_sha256 = "1b2c3e80347b35fb5811619f3aeae75f05dd4e635ffef7620141be7ed3041eb3"
    license = "CC BY 4.0"

  strings:
    $config = "\\Software\\MyApp\\Config" ascii wide
    $workdir = "WorkDir do registro:" ascii wide
    $helper = "sk4d.dll" ascii wide nocase
    $stage = "Procurando .dmc/.dkd em:" ascii wide
    $missing = "Nenhum arquivo .dkd/.tda encontrado em:" ascii wide
    $hollow = "=== Process Hollowing (Stealth Mode) ===" ascii wide
    $surrogate = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegSvcs.exe" ascii wide nocase

  condition:
    uint16(0) == 0x5a4d and pe.machine == pe.MACHINE_I386 and
    $config and $helper and $hollow and $surrogate and
    1 of ($workdir, $stage, $missing) and
    pe.imports("kernel32.dll", "CreateProcessW") and
    pe.imports("kernel32.dll", "ResumeThread")
}
