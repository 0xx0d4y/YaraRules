rule win_eternidade_autoit_wrapper_102026 {
  meta:
    author = "0x0d4y"
    description = "Detects the Eternidade AutoIt wrapper that delays, decodes an embedded script, and executes it"
    reference = "https://0x0d4y.blog/inside-brazils-financial-malware-ecosystem-deep-dive-into-eternidade-stealer/"
    date = "2026-10-18"
    score = 90
    malware_family = "win.eternidade"
    component = "autoit_wrapper"
    sample_sha256 = "1329da8687cc8f9733b99533f49715520ada89a6cdddc93dfd03505f101454a7"
    license = "CC BY 4.0"

  strings:
    $delay = "Random(61000, 91000, 1)" ascii
    $chunks = "Random(15, 25, 1)" ascii
    $decoder = "CryptStringToBinaryA" ascii
    $random_name = "Chr(Random(97, 122, 1))" ascii
    $execute = "/AutoIt3ExecuteScript" ascii
    $cleanup = "OnAutoItExitRegister('_CT')" ascii
    $extension = "& '.au3'" ascii

  condition:
    filesize > 25KB and filesize < 100KB and
    uint32be(0) == 0x234e6f54 and
    5 of them
}
