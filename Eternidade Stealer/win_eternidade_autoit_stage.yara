rule win_eternidade_autoit_stage_102026 {
  meta:
    author = "0x0d4y"
    description = "Detects the decoded Eternidade AutoIt banking-trigger, decryptor, and reflective PE loader"
    reference = "https://0x0d4y.blog/inside-brazils-financial-malware-ecosystem-deep-dive-into-eternidade-stealer/"
    date = "2026-10-18"
    score = 95
    malware_family = "win.eternidade"
    component = "decoded_autoit_stage"
    sample_sha256 = "def2679e5c594e716c2eba6ffd0de2d2cf5d0f2d84ee87c079ee4c81a672024d"
    license = "CC BY 4.0"

  strings:
    $decryptor = "Func comquefaz($bOrigem, $iChave0 = 3333, $iChave1 = 3434, $iChave2 = 1000)" ascii
    $state = "$iChave2 = BitAND((BitAND(($iResultado + $iChave2), 0xFF) * $iChave0 + $iChave1), 0xFFFF)" ascii
    $decompress = "RtlDecompressFragment" ascii
    $manual_map = "Func botaelamemoria($bPE)" ascii
    $config = "HKEY_CURRENT_USER\\Software\\MyApp\\Config" ascii
    $panel = "https://secretopanel2.site/principal/aNuEntity.php" ascii
    $surrogate = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegSvcs.exe" ascii

  condition:
    filesize > 20KB and filesize < 100KB and
    $decryptor and $state and $decompress and $manual_map and
    2 of ($config, $panel, $surrogate)
}
