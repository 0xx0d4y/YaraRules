import "pe"

rule win_astaroth_final_payload_code_102026 {
  meta:
    author = "0x0d4y"
    description = "Detects the Astaroth/Guildma banking core using intrinsic protected-string decoder code"
    date = "2026-10-18"
    score = 100
    malware_family = "win.astaroth"
    component = "banking_core"
    sample_sha256 = "74ab591bf4a271f136a65316f729dfb98b3f2270435ba688d1a030501e3d6938"
    license = "CC BY 4.0"

  strings:
    $code_mod255_delta = {
      8B 45 ?? 3B 45 ?? 7E ?? 8B 45 ?? 29 45 ?? EB ??
      8B 45 ?? 3B 45 ?? 7F ?? 8B 45 ?? 05 FF 00 00 00
      2B 45 ?? 89 45 ??
    }

    $code_radix25_pairs = {
      0F B7 00 83 E8 41 8D 04 80 8D 04 80
      8B 55 ?? 0F B7 52 02 83 EA 41 03 C2
      2B 45 ?? 83 E8 64 89 45 ??
    }

    $code_nested_alphabet = {
      66 83 7D ?? 41 72 ?? 66 83 7D ?? 4B 77 ??
      0F B7 45 ?? 83 E8 41 03 C0 8D 04 80 89 45 ??
      66 83 7D ?? 30 75 ?? 83 45 ?? 0A
      [0-48]
      83 7D ?? 01 7C ?? 83 7D ?? 6D 7F ??
    }

    $code_decode_pipeline = {
      8D 55 ?? 8B 45 ?? E8 ?? ?? ?? ??
      8B 45 ?? 8D 55 ?? E8 ?? ?? ?? ??
      8B 55 ?? 8D 45 ?? B9 00 00 00 00 E8 ?? ?? ?? ??
      8B 45 ?? 8D 55 ?? E8 ?? ?? ?? ??
      8B 55 ?? 8D 45 ?? E8 ?? ?? ?? ??
      8B 45 ?? 8D 55 ?? E8 ?? ?? ?? ??
    }

    $project = "pxsaltisthimgruklia" ascii wide nocase

  condition:
    uint16(0) == 0x5a4d and
    pe.number_of_sections >= 9 and
    3 of ($code_*) and
    ( $project or
      (pe.imports("user32.dll", "SetWindowsHookExW") and
       pe.imports("user32.dll", "GetClipboardData") and
       pe.imports("gdi32.dll", "BitBlt")) )
}
