import "pe"

rule elf{
	strings:
		$magic = {7f 45 4c 46}
	condition:
		$magic at 0
}

rule pe32{
	strings:
		$mz = "MZ"
	condition:
		pe.characteristics and $mz at 0 and uint32(uint32(0x3C)) == 0x00004550

}

rule upx{
	strings:
		$upx = "upX" wide ascii
		$upx0 = "UPX0" wide ascii
		$upx1 = "UPX1" wide ascii
		$upx2 = "UPX2" wide ascii
		$upxx = "UPX!" wide ascii

	condition:
		(2 of ($upx0, $upx1, $upx2)) or $upxx or $upx
}

rule wannacry{
	strings:
		$wannacry1 = "WanaCrypt0r" wide ascii
		$wannacry2 = "WANACRY!" ascii
		$wannacry3 = "WANNACRY"
		$wannacry4 = "WNCRYT"
		$wannacry5 = "wnry" fullword
		$wannacry6 = "WNcry@2ol7"
		$wannacry7 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
		$wannacry8 = "LANMAN1.0"
		$wannacry9 = "LANMAN2.1"
		$wannacry10 = "%s -m security"
		$wannacry11 = "PlayGame"
		$msg = "CryptDecrypt"

		$smb1 = "SMB3"
		$smb2 = "SMBu"
		$smb3 = "SMBs"
		$smb4 = "SMBr"

		$path1 = "C:\\%s\\qeriuwjhrf"
		$path2 = "cmd.exe /c \"%s\""
		$path3 = "__TREEID__PLACEHOLDER__"
		$path4 = "__USERID__PLACEHOLDER__@"

		$inet1 = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
		$inet2 = "\\\\192.168.56.20\\IPC$" fullword wide ascii
		$inet3 = "\\\\172.16.99.5\\IPC$"

		$windows1 = "Windows for Workgroups 3.1a" ascii
		$windows2 = "Windows 2000 2195" wide ascii
		$windows3 = "Windows 2000 2195" ascii

		$proc1 = "tasksche.exe"
		$proc2 = "TaskStart"
		$proc3 = "Global\\MsWinZonesCacheCounterMutexA"



	condition:
		pe32 and ((3 of ($wannacry*)) and (($windows1 or $windows2 or $windows3) or$smb1 or $smb2 or $smb3 or $smb4 or $proc1 and $proc2 and $proc3 or $msg or $path1 or $path2 or ($path3 and $path4) or ($smb1 or $smb2 or $smb3 or $smb4)) and ($inet1 or $inet2 or $inet3))
}

rule mirai{
	strings:
		$mirai1 = "/dev/watchdog" ascii
		$mirai2 = "/dev/misc/watchdog" ascii
		$mirai3 = "POST /cdn-cgi/" fullword ascii

		$dev1 = "/dev/null" ascii
		$dev2 = "/sys/devices/system/cpu" ascii
		$dev3 = "/proc/stat" ascii
		$dev4 = "/proc/cpuinfo" ascii
		$dev5 = "/proc/net/tcp" ascii

		$broken1 = "PTRh"
		$broken2 = "UWVS"
		$broken3 = "D$DP"
		$broken4 = {44 24 ?? ??}
		$broken5 = {4c 24 ?? ??}
		$broken6 = "RPWV"
		$broken7 = "XSZW"

		$botnet = "Botnet Made By greek.Helios"

		$string1 = "LCOGQGPTGP" fullword ascii
		$string2 = "PMMV" fullword ascii
		$string3 = "TKXZT" fullword ascii
		$string4 = "CFOKL" fullword ascii
		$string5 = "ZOJFKRA" fullword ascii
		$string6 = "FGDCWNV" fullword ascii
		$string7 = "HWCLVGAJ" fullword ascii
		$string8 = "QWRRMPV" fullword ascii
		$string9 = "RCQQUMPF" fullword ascii
		$string10 = "WQGP" fullword ascii
		$string11 = "RCQQ" fullword ascii
		$string12 = "QOACFOKL" fullword ascii
		$string13 = "cFOKLKQVPCVMP" fullword ascii nocase
		$string14 = "OGKLQO" fullword ascii
		$string15 = "QGPTKAG" fullword ascii
		$string16 = "QWRGPTKQMP" fullword ascii
		$string17 = "EWGQV" fullword ascii
		$string18 = "W@LV" fullword ascii
		$string19 = "OMVJGP" fullword ascii
		$string20 = "QUKLEKLUKVJOG" fullword ascii
		$string21 = "NKQVGLKLE" fullword ascii

	condition:
		elf and filesize < 100KB and ((any of ($broken*)) or $botnet or ((2 of ($string*)) and ((1 of ($dev*)) and ($mirai1 or $mirai2 or $mirai3))))
}

rule blouiroet{
	strings:
		$dropped = "c:\\programdata\\temp1.exe" ascii
		$domain1 = "https://kazy-bazy.000webhostapp.com/local.rar" ascii
		$domain2 = "http://mine.zarabotaibitok.ru/Downloads/Modul/load.exe" ascii

		$string1 = {36 08 37 0c 37 30 37 34 37 38 37 3c 37 40 37 44 37 48 37 4c 37 50 37 54 37 60 37 64 37 68 37 6c 37 70 37 74 37 78 37 7c 37}
	condition:
		pe32 and $dropped and $string1 or ($domain1 or $domain2)
}

rule zombieboy{
	strings:
		$zboy1 = "C:\\Windows\\System32\\sys.exe"
		$zboy2 = "http://ca.fq520000.com:443/123.exe"
		$zboy4 = "C:\\Users\\ZombieBoy\\Documents\\Visual Studio 2017\\Projects\\nc\\Release\\nc.pdb"
	condition:
		any of them
}

rule practicalmalwareanalysis{
    meta:
        description = "Unpacking Exercices from the Book Practical Malware Analysis: The Hands-On Guide to Dissecting Malicious Software by Michael Sikorski and Andrew Honig"
    strings:
        $practical1 = "http://www.malwareanalysisbook.com/ad.html" wide ascii
        $practical2 = "http://www.practicalmalwareanalysis.com"
    condition:
        pe32 and ($practical1 or $practical2)
}

rule unpackme{
    meta:
        description = "PEtite 1.4 Unpacking (reversing) challenge from tuts4you. Goal: Remove packing. This sample also includes ElDorado malware (VirusTotal)"
    strings:
        $unpackingchallenge = "Cool....you made it"
    condition:
        pe32 and $unpackingchallenge
}

rule hajime{
	strings:
		$hajime = "Cortex-A5"
	condition:
		$hajime
}

rule empty{
	condition:
		filesize == 0KB
}