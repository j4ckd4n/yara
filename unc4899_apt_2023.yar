rule M_APT_Backdoor_STRATOFEAR_1 {
    meta:
        author = "Dan Kelly"
        date_created = "2023-07-21"
        date_modified = "2023-07-21"
        description = "Detects instances of STRATOFEAR"
        md5 = "6d8194c003d0025fa92fbcbf2eadb6d1"
    strings:
        $str1 = "-alone" ascii
        $str2 = "-psn" ascii
        $str3 = "embed://" ascii
        $str4 =  "proc_data" ascii
        $str5 = "udp://" ascii
        $str6 =  "Path : %s" ascii
        $str7 = "127.0.0.1" ascii
    condition:
        ((uint32(0) == 0xBEBAFECA) or (uint32(0) == 0xFEEDFACE) or (uint32(0) == 0xFEEDFACF) or (uint32(0) == 0xCEFAEDFE)) and all of them
}

rule FE_APT_Backdoor_MacOS_FULLHOUSE_1{
    meta:
        author = "joseph.reyes"
        date_created = "2020-05-04"
        date_modified = "2020-05-04"
        md5 = "b0611b1df7f8516ad495cd2621d273b9"
        rev = 3
        sid = 409583
        tag = "FULLHOUSE.DOORED"
        threatmatrix = "https://threatmatrix.eng.fireeye.com/hpc/results-v2/4abb563d-cd42-4795-98c9-7af2a2687652/"
        ticket = "TIS-39181"
        weight = 100
    strings:
        $s1 = /<\x00%\x00l?\x00s\x00>\x00<\x00%\x00l?\x00s\x00>\x00<\x00%\x00l?\x00s\x00>/ wide
        $sb1 = { E8 [4-32] 83 F8 ?? 0F 87 [4] 48 8D 0D [4] 48 63 04 81 48 01 C8 FF E0 }
    condition:
        ((uint32(0) == 0xBEBAFECA) or (uint32(0) == 0xFEEDFACE) or (uint32(0) == 0xFEEDFACF) or (uint32(0) == 0xCEFAEDFE)) and all of them
}

rule M_APT_Backdoor_TIEDYE_1 {
    meta:
        author = "Dan Kelly"
        date_created = "2023-07-21"
        date_modified = "2023-07-21"
        description = "Detects instances of TIEDYE"
        md5 = "15bfe67e912f224faef9c7f6968279c6"
    strings:
        $str1 = "%s/Library/LaunchAgents/com.%s.agent.plist" ascii
        $str2 = "/Library/LaunchDaemons/com.%s.agent.plist" ascii
        $str3 = "%s/.plugin%04d.so" ascii
        $str4 = "sw_vers -productVersion" ascii
        $str5 = "!proxy=http://" ascii
        $str6 = "Content-Type: application/octet-stream" ascii
        $str7 = "<key>RunAtLoad</key>" ascii
        $str8 = "<string>com.%s.agent</string>" ascii
        $str9 = "%sProxy-Authorization: %s" ascii
        $str10 = "!udp_type"
        $str11 = "!http="
    condition:
        ((uint32(0) == 0xBEBAFECA) or (uint32(0) == 0xFEEDFACE) or (uint32(0) == 0xFEEDFACF) or (uint32(0) == 0xCEFAEDFE)) and all of them

}
