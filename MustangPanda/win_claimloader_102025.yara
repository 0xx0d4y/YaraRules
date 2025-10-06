rule win_claimloader_102025 {
  meta:
      author = "0x0d4y"
      description = "Detects intrinsic strings and the string decryption routine used by ClaimLoader."
      date = "2025-10-06"
      score = 100
      reference = "https://0x0d4y.blog/mustang-panda-employ-publoader-through-claimloader-yes-another-dll-side-loading-technique-delivery-via-phishing/"
      yarahub_reference_md5 = "308f9f8dbc4e48a2648bfcb27f205a4a"
      yarahub_uuid = "5011dc0b-0642-4ea3-87d5-0c4a26d47bed"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      malware_family = "win.claimloader"

  strings:
      $s1 = "C:\\ProgramData\\AdobeLicensingPlugin" ascii wide fullword
      $s2 = "C:\\ProgramData\\AdobeLicensingPlugin\\WF_Adobe_licensing_helper.exe" ascii wide fullword
      $s3 = "Licensing" ascii wide fullword
      $s4 = "LdrLoadDll" ascii wide fullword
      $s5 = "LdrGetProcedureAddress" ascii wide fullword

      $decrypt_str_api = { 0F 28 0D ?? ?? ?? ?? 33 C0 85 D2 74 42 83 FA 20 72 30 56 8B F2 83 E6 E0 0F 1F 84 00 00 00 00 00 0F 10 04 01 66 0F EF C1 0F 11 04 01 0F 10 44 01 10 66 0F EF C1 0F 11 44 01 10 83 C0 20 3B C6 72 DF 5E 3B C2 73 09 80 34 08 ?? 40 3B C2 72 F7 C3 }

  condition:
      uint16(0) == 0x5A4D and ( 3 of ($s*) or $decrypt_str_api )
}


