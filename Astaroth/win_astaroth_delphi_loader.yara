import "pe"

rule win_astaroth_delphi_loader_102026 {
  meta:
    author = "0x0d4y"
    description = "Detects the Astaroth Delphi loader implementing add-0x2A decoding and RegSvcs process hollowing"
    date = "2026-10-18"
    score = 95
    malware_family = "win.astaroth"
    component = "delphi_loader"
    sample_sha256 = "d7bfb7daa2feed448d3c1ad9bb3799c75e39ead2bb42e297a44ec804ab77c9b4"
    license = "CC BY 4.0"

  strings:
    $decode_loop = {
      0F B6 04 10 33 D2 8A 55 ?? 2B C2 05 00 01 00 00
      25 FF 00 00 80 79 ?? 48 0D 00 FF FF FF 40
      8B 55 ?? 8B 4D ?? 88 04 0A FF 45 ?? FF 4D ?? 75 ??
    }

  condition:
    uint16(0) == 0x5a4d and
    $decode_loop and
    pe.imports("kernel32.dll", "CreateProcessW") and
    pe.imports("kernel32.dll", "WriteProcessMemory") and
    pe.imports("ntdll.dll", "NtUnmapViewOfSection")
}
