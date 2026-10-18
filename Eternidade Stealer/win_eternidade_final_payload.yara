import "pe"

rule win_eternidade_final_payload_code_102026 {
  meta:
    author = "0x0d4y"
    description = "Detects the Eternidade banking stealer using its intrinsic noisy-hex command-string decoder"
    reference = "https://0x0d4y.blog/inside-brazils-financial-malware-ecosystem-deep-dive-into-eternidade-stealer/"
    date = "2026-10-18"
    score = 100
    malware_family = "win.eternidade"
    component = "banking_stealer"
    sample_sha256 = "caee37ada944021465739c1ac2f932c76e202769070e2f92a7da452106a313a0"
    license = "CC BY 4.0"

  strings:
    $code_decode_core = {
      0F B6 04 18 2C 05 8B 5D ?? 32 44 53 FE
      BB ?? ?? ?? ?? 32 44 4B FE
      8B 5D ?? 8B 75 ?? 88 04 33 42 41
      [0-24]
      3B C2 7D ?? BA 01 00 00 00
      83 F9 13 7E ?? B9 01 00 00 00
      FF 45 ?? FF 4D ?? 75 ??
    }
    $code_filter_hex_noise = {
      0F B7 44 58 FE 83 C0 D0 66 83 E8 0A 72 ??
      83 C0 F9 66 83 E8 06 72 ??
      83 C0 E6 66 83 E8 06 73 ??
    }
    $code_hex_pairs = {
      8B D3 03 D2 42 B9 02 00 00 00 8B 45 ?? E8 ?? ?? ?? ??
      [0-32]
      8B 45 ?? E8 ?? ?? ?? ?? 8B 55 ?? 8B 12 88 04 1A 43 4E 75 ??
    }
    $code_strip_prefix = {
      83 F8 08 7E ?? 8B DA 85 DB 74 ?? 8B 5B FC
      8B 45 ?? 50 8B CB 83 E9 08 BA 09 00 00 00
      8B 45 ?? E8 ?? ?? ?? ??
    }

    $salt = "MeuSaltPessoal#2024" ascii wide

  condition:
    uint16(0) == 0x5a4d and
    pe.machine == pe.MACHINE_I386 and
    pe.number_of_sections >= 9 and
    $code_decode_core and
    2 of ($code_filter_hex_noise, $code_hex_pairs, $code_strip_prefix) and
    ( $salt or
      (pe.imports("user32.dll", "SetWindowsHookExW") and
       pe.imports("user32.dll", "GetClipboardData") and
       pe.imports("gdi32.dll", "BitBlt")) )
}
