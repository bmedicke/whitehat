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
  * nicht zu früh, da die Auswertung von PCR Tests eine gewisse Zeit benötigt

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

## BOF ohne ASLR

## BOF mit ASLR

# Quellen

* https://github.com/bmedicke/REED
