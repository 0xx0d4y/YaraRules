rule apt_scoringmathtea_lazarus_112025 {
    meta:
        author = "0x0d4y"
        description = "Detects the ScoringMathTea RAT, associated with the Lazarus group, based on unique string and hashing algorithm patterns."
        date = "2025-11-10"
        score = 100
        reference = "https://0x0d4y.blog/arsenal-analysis-of-a-nation-state-actor-an-in-depth-look-at-lazarus-scoringmathtea/"
        reference_md5 = "cc9cf047aec871cefb1c7d4b8d5d3432"
        uuid = "9702536f-8fe2-49e4-8d01-18f6b1fdadf3"
        malpedia_family = "win.scoringmathtea"

    strings:
        $custom_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36 Edg/107.0.1418.42" ascii wide fullword
        $plugin_export = "exportfun" ascii wide fullword
        $html_filtering = "DOCTYPE" ascii wide fullword
        $hash_algorithm = { 41 ?? ?? ?? ?? ?? EB 1A 41 8B C9 C1 E1 ?? 41 8B C1 C1 F8 ?? 03 C8 40 0F BE C7 03 C8 44 33 C9 49 FF C0 }
        $crc32_custom_algorithm = { 41 8B D0 BF ?? ?? ?? ?? C1 E2 ?? 8B C2 8D 0C 12 8B D1 81 F2 ?? ?? ?? ?? 85 C0 0F 49 D1 48 83 EF ?? 75 E8 41 89 12 41 FF C0 49 83 C2 ?? 41 81 F8 ?? ?? ?? ?? 7C CA 8B D6 45 85 C9 74 1D 41 0F B6 03 49 FF C3 8B CA 48 C1 E9 ?? 48 33 C8 C1 E2 ?? 33 ?? ?? ?? 41 83 C1 }

    condition:
        uint16(0) == 0x5a4d and
        (any of ($hash_algorithm, $crc32_custom_algorithm)) and     
        (any of ($custom_user_agent, $plugin_export, $html_filtering))
}