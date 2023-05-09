rule Volumiser_Executable {
  meta:
    author = "Arnas A."
    id = "771da8a0-f011-4da0-9a14-cbbf853975d3"
    fingerprint = "A3E02664ED9FB3E76ACDBB654CF0EACB18EE815011D85266B1DEBDB773972776"
    creation_date = "2023-04-27"
    modified_date = "2023-04-27"
    threat_name = "windows.volumiser"
    severity = 5
    arch_context = "x86, arm64, x64"
    scan_context = "file"
    os = "windows"
  strings:
    $a1 = { 56 00 6F 00 6C 00 75 00 6D 00 69 00 73 00 65 00 72 }
    $a2 = { 46 00 61 00 69 00 6C 00 65 00 64 00 20 00 74 00 6F 00 20 00 6F 00 70 00 65 00 6E 00 20 00 72 00 61 00 77 }
    $a3 = { 46 00 61 00 69 00 6C 00 65 00 64 00 20 00 74 00 6F 00 20 00 71 00 75 00 65 00 72 00 79 00 20 00 64 00 69 00 73 00 6B 00 20 00 67 00 65 00 6F 00 6D 00 72 00 74 00 72 00 79 00 00 11 52 00 61 00 77 }
  condition:
    all of them
}
