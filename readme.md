* `alt-o` options
* `alt-c` CPU
* `alt-l` log (mona output)

---

* `!mona config -set workingfolder Z:\WH3`
* run program in debugger!
* `!mona jmp -n -r esp -cm safeseh=false,rebase=false,aslr=false`
  * find `jmp esp` (`-r` is target register)
  * `-n` skips addresses starting with NULL byte
  * `-cm` speficy options
  * this took very long! (much faster with `-cm`!)
* let's use `0x1a113749` gen_ff.dll
