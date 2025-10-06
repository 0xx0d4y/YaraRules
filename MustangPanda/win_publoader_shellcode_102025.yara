rule win_publoader_shellcode_102025 {
  meta:
      author = "0x0d4y"
      description = "Detects the ROR13 and a custom decode algorithm, of Publoader."
      date = "2025-10-06"
      score = 100
      reference = "https://0x0d4y.blog/mustang-panda-employ-publoader-through-claimloader-yes-another-dll-side-loading-technique-delivery-via-phishing/"
      yarahub_reference_md5 = "c5174c996d047bc03ab02c726ccbd2ab"
      yarahub_uuid = "74ad2656-8c60-42b1-9a21-2e6c00a96af0"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      malware_family = "win.publoader"

  strings:
      $ror13 = { 8B 45 08 0F B7 08 85 C9 74 ?? 8B 55 08 0F B7 02 89 45 ?? 8B 4D 08 83 C1 ?? 89 4D 08 8B 55 ?? C1 EA ?? 89 55 ?? 8B 45 ?? C1 E0 ?? 89 45 ?? 8B 4D ?? 0B 4D ?? 89 4D ?? 8B 55 ?? 03 55 ?? 89 55 }
      $custom_decoding_algorithm = { 8B 45 ?? 03 45 ?? 0F BE 08 8B 45 ?? 83 C0 ?? 33 D2 BE ?? ?? ?? ?? F7 F6 0F BE 54 15 ?? 33 CA 8B 45 ?? 03 45 ?? 88 08 }

  condition:
      uint16(0) == 0x5A4D and $ror13 and $custom_decoding_algorithm
}
