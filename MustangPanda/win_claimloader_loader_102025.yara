rule win_claimloader_loader_102025 {
  meta:
      author = "0x0d4y"
      description = "Detects intrinsic strings of ClaimLoader loader."
      date = "2025-10-06"
      score = 100
      reference = "https://0x0d4y.blog/mustang-panda-employ-publoader-through-claimloader-yes-another-dll-side-loading-technique-delivery-via-phishing/"
      yarahub_reference_md5 = "be4ed0d3aa0b2573927a046620106b13"
      yarahub_uuid = "85aa83c1-6cbf-47f1-9be3-2163aca4d08d"
      yarahub_license = "CC BY 4.0"
      yarahub_rule_matching_tlp = "TLP:WHITE"
      yarahub_rule_sharing_tlp = "TLP:WHITE"
      malware_family = "win.claimloader"

  strings:
      $s1 = "G:\\CLIENT\\fhbemb\\src\\bin\\Release\\fhjyy.pdb" ascii wide nocase
      $s2 = "ProcessMain" ascii wide
      $s3 = "\\..\\..\\embcore\\" ascii wide
      $s4 = "3.3325.1758.0" ascii wide
      $s5 = "libjyy.dll" ascii wide nocase
      $s6 = "fhbjyy.exe" ascii wide nocase

  condition:
      uint16(0) == 0x5A4D and
      3 of ($s*)
}
