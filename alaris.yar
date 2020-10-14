import "pe"

rule alaris 
{
    meta:
        description = "Find all stock Melange Loaders"
        author = "Joshua Faust"
        date = "2020/10/14"
    strings:
        $ = "[!] ERROR" fullword ascii wide
		$ = "C:\\Windows\\System32\\mobsync.exe" fullword wide
        $ = "gexplorer.exe" fullword wide
        $ = { 70 76 20 f2 3f 4c 4c 10 45 fb 50 93 d8 d1 c9 fb 6c 30 45 88 dd b2 f4 af 9c 1c 22 13 26 67 24 bd }
        $ = { 89 54 7f 64 c0 ce 3a 44 f0 ee af ?? a8 dc 6b 65 }
    condition:
    	 pe.is_pe and 3 of them
}