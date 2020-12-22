# GDB

<!-- TOC depthFrom:3 depthTo:3 withLinks:1 updateOnSave:1 orderedList:0 -->

- [Getting started](#getting-started)
- [Set](#set)
- [Show](#show)
- [Print](#print)
- [eXamine](#examine)
- [Breakpoints](#breakpoints)
- [Watchpoints](#watchpoints)
- [Stepping](#stepping)
- [Loop](#loop)
- [Structs](#structs)
- [Buffers](#buffers)
- [Buffer filling](#buffer-filling)
- [Understanding where you are](#understanding-where-you-are)
- [Registers](#registers)
- [Stack](#stack)
- [Memory](#memory)
- [Rat Holes](#rat-holes)
- [Shell](#shell)
- [Cool commands](#cool-commands)

<!-- /TOC -->

### Getting started
##### Install the gef extension
`https://gef.readthedocs.io/en/master/#setup`
##### gdb version
`show version`
##### From command line
`gdb my_app `
##### From command line with some A's
`gdb --args format_zero AAAA`
##### From command line with lots of A's
`gdb --args format_zero $(python -c 'print "A"*10')`
##### Attach after gdb opened to process ID
`attach pid`
##### After gdb opened, load file ( symbol table )
`file format_zero`
##### Run file
`run`
##### Disassemble
`disas start_level`
##### Disassemble main from command line, with gdb
`gdb -batch -ex 'file format_one' -ex 'disassemble main'`
##### Disassemble and look for compare instructions
`gdb -batch -ex 'file format_one' -ex 'disassemble main' | grep -i cmp`

### Set
##### Integer
`set $foo = 3`
##### String
`set $str = "hello world"`
##### Instruction flavor
`set disassembly-flavor intel`
##### Environment variable (LD_PRELOAD)
`set environment LD_PRELOAD=./mylib.so`
##### Environment variable ( PATH )
`set env PATH=``perl -e 'print "A" x 65'`
##### Set environment variable
`python gdb.execute("set environment payload=%x%x%x%x")`
### Show
##### Show env payload
`show env payload`
##### All environment variables
`show environment`
##### All one env variable
`show environment PATH`

### Print
```
gef➤  print &changeme
$2 = (int *) 0x601050 <changeme>

gef➤  print changeme
$3 = 0xff

gef➤  print "foobar"
$1 = "foobar"

gef➤  print $1
$2 = "foobar"

(gdb) p/x $foo
$1 = 0x3

(gdb) p $foo
$2 = 3

(gdb) p 5+5
$5 = 0xa

p/d 0xffffd59c - 0xffffd560
$35 = 60

p/tz $eip             // print leading zeroes
$4 = 0x08049201

gef➤  x/s $esp
0xffffd570:	"AAAA"

gef➤  p $esp
$1 = (void *) 0xffffd570

gef➤  p (char *) $esp
$2 = 0xffffd570 "AAAA"

(gdb) p $bar = "hello"
$3 = "hello"

(gdb) p/x $bar
$4 = {0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x0}

(gdb) p $bar
$5 = "hello"
```
### eXamine
##### Print stack
`x/24wx $esp`
##### Print bytes 4 bytes x 9 addresses starting at 0x6c00
`x/9wx 0x6c00`
##### Print 256 individual bytes from address 350
`x/256bx 0x350`
##### Print 4-bytes 32 times from address 0x6c00
`x/32wx 0x6c00`
##### Print data at memory address as Int
`x/d 0x7ffe76d25c50`
##### Print data at memory address as Hex
`x/x 0x7ffe76d25c50`
##### Current instruction
`x/i $pc`
##### Current next two instructions
`x/2i $pc`
##### Current 6 instructions from last instruction ( 113 - 108 = 5)
```
x/6i $pc-5
   0x4006b3 <main+108>:	call   0x400540 <sprintf@plt>
=> 0x4006b8 <main+113>:	mov    eax,DWORD PTR [rbp-0x10]
   0x4006bb <main+116>:	test   eax,eax
   0x4006bd <main+118>:	je     0x4006cd <main+134>
   0x4006bf <main+120>:	lea    rdi,[rip+0x102]        # 0x4007c8
   0x4006c6 <main+127>:	call   0x400510 <puts@plt>
```   
### Breakpoints
##### Help
`help breakpoints`
##### Break on symbol name
`b atoi`
##### Breakpoint list
`info breakpoints`
##### Disable all
`disable breakpoints`
##### Delete breakpoint at current instruction
`clear`
##### Delete breakpoint 2
`del br 2`
##### Delete breakpoints
`delete breakpoints 1-8`
##### Delete ALL breakpoints
`d br`
##### Break on address
`b *0x04006b3`
##### Break on start of function + 24
`b *start_level + 24`
##### Disassemble. Then break after interesting call
`br *main + 113`
##### Break on mangled name
`b _ZN8password11checkLengthEi`
##### Break if Register ( Second Argument: RSI ) set to 6
`break if $rsi = 0x38`
##### break if
`break passwordcheck if 0 == 0`
##### Run debugger commands on Breakpoint 1
```
command 1
Type commands for breakpoint(s) 1, one per line.
End with a line saying just "end".
>print "fluffy foobar"
>end
```

### Watchpoints
##### Watch memory of stack variables ( no debug symbols )
`memory watch 0x7ffca5211480+0x28 8 qword`
##### Hardware watchpoint - with debug symbols - char buffer
`watch *(char(*)[32])(locals.dest)`
##### Hardware watchpoint - with debug symbols - int
`watch *(int)(locals.changeme)`

### Stepping
```
nexti 3     /* run next 3 instructions */

finish      /* continue execution of current function and then stop */
```

### Loop
```
set $loop = 5
while $loop > 0
 >output "$loop is "
 >output $loop
 >echo \n
 >set $loop = $loop - 1
 >end
"$loop is "0x5
"$loop is "0x4
"$loop is "0x3
"$loop is "0x2
"$loop is "0x1
```
#### Malloc
```
gef> p (int)malloc(6)
$7 = 0xb7ffd020
```
### Structs
```
(gdb) ptype /o struct locals
```
### Buffers
##### Find size of buffer ( memset )
`disassemble main` and find useful `apis`.  For example, if `memset` is called:

> void *memset(void *b, int c, size_t len);

If you break on the `memset` call, you find two useful things; the address of `buffer` and the `length` of the buffer.
```
memset@plt (
   $rdi = 0x00007fffffffe440 → 0x0000000000000000,
   $rsi = 0x0000000000000000,
   $rdx = 0x0000000000000100,
   $rcx = 0x00007ffff7af4154 → 0x5477fffff0003d48 ("H="?)
)
```
The third value, the buffer length is represented in hex.  You can see the `buffer` is `256` chars long.
```
gef➤  p/d 0x100
$4 = 256
```
##### Find size of buffer ( strncpy )
The second API call is `strncpy`.  This is less famous than `strcpy`.  The latter doesn't have the `strncpy's len` argument to mitigate buffer overflows:

> char * strncpy(char * dst, const char * src, size_t len);

If we break on `strncpy`.  It was passed:
```
strncpy@plt (
   $rdi = 0x00007fffffffe440 → 0x0000000000000000,
   $rsi = 0x00007fffffffe851 → "%256xAAAAAAAAAAAAAAAA",
   $rdx = 0x0000000000000100        <-- 256 char buffer
)
```
That re-confirms the address of the buffer and it's length of `256` characters.

##### Target register
`0x00007fffffffe440`
##### Watch buffer
`memory watch p/x 0x00007fffffffe440 10 qword`
##### Print each byte
`x/256bx 0x00007fffffffe440`
##### Print only the buffer
`x/64wx 0x00007fffffffe440`


### Buffer filling
#### argv[1]
##### Prepare input outside of debugger ( and reverse bytes )
`python -c 'print "\x08\x04\xa0\x30"[::-1] + "%p"*14 + "%n"' > change_me_bytes.hex`
##### Check the bytes
```
# xxd change_me_bytes.hex
00000000: 30a0 0408 2570 2570 2570 2570 2570 2570  0...%p%p%p%p%p%p
00000010: 2570 2570 2570 2570 2570 2570 2570 2570  %p%p%p%p%p%p%p%p
00000020: 256e 0a                                  %n.
```
##### Inside of gdb
`run $(cat change_me_bytes.hex)`

##### Overfill a buffer with gets() or strcpy() or Environment Variable
```
$ python -c 'print "A"*(80) + "\x44\x05\x01\x00"' | ./stack-four
$ cat ~/128chars | ./stack-five
```
##### Works with sprintf() or gets()
```
# python -c 'print "%p"*10' > payload.txt
# gdb format_zero

r < ~/payload.txt
```
##### inside gdb.  Passing in arguments values ( for `scanf`, `strcpy` etc )
```
r payload.txt

run $(python -c 'print "A" * 20')

run $(python -c 'print "%268x" + "\x41\x41\x41\x41"')

run `printf "\x54\x10\x60"`%.fx%4\$hn%.ex%5\$hn

run $(echo -e "\x54\x10\x60\x00%x%x%x%x%x%x%x%x%x%x%x%n.")
```
##### Troubleshooting python3 buffer filling
When you hit a non-readable ASCII character. Reference [here][ba369178].

  [ba369178]: https://stackoverflow.com/questions/42884251/why-is-the-output-of-print-in-python2-and-python3-different-with-the-same-string "python_2_and_3_byte_differences"

### Understanding where you are
`main info sec`
##### whatis
```
gef> whatis 0x000106d8
type = int

  [961d8f92]: https://stackoverflow.com/questions/42884251/why-is-the-output-of-print-in-python2-and-python3-different-with-the-same-string "python3_byte_str"

gef> whatis "hello"
type = char [6]

```
#### Shared Libraries
```
info sharedlibrary
```
#### Locations of system calls
```
gef> x/x strcpy
0xffffb7f72050 <strcpy>:	0xf3
gef> x/x system
0xffffb7f9fee4 <system>:	0xff
gef> x/x printf
0xffffb7faafa4 <printf>:	0xff
```
#### Set and Print Variable
```
gef> p getenv ("PATH")
'getenv' has unknown return type; cast the call to its declared return type

gef> p (char *) getenv ("PATH")
$8 = 0xffffffffffa2 "/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"

// https://sourceware.org/gdb/onlinedocs/gdb/Calling.html
(gdb) p ((char * (*) (const char *)) getenv) ("PATH")

gef> set env FooBarEnvVariables=`perl -e 'print "A" x 65'`

gef> x/s *((char **)environ)
0xfffefed4:	"LS_COLORS="
```
### Registers
```
reg
info registers
```
### Stack
##### Get stack size
`set $stack_size = $rbp - $rsp`         # 272
##### Calculate max overflow
`p/d $stack_size -256`                  # 16
##### Print stack
`x/272wx $rsp`
### Memory
```
gef> x/100wx $sp-200     // check overflowed Stack

gef> x/24x $sp          // read hex address from Stack pointer

gef> x/2w $sp        <--- print from stack pointer
0xfffefd00:	0xfffefd84	0x00000001	0x00000011	0xf77f0288

gef> x/wx 0xfffefd84        <--- print memory address
0xfffefd84:	0xfffefe8e

gef> x/s 0xfffefe8e         <-- string
0xfffefe8e:	"/opt/phoenix/arm/stack-two"

gef> find $sp, +96,0x000105bc           // find Return address on Stack
0xfffefd64
1 pattern found.
```
#### Calculate Sizes
```
gef> p 0xfffefd74 - 0xfffefd20
$9 = 0x54

gef> p/u 0x54
$10 = 84

gef> p/u 0xfffefd74 - 0xfffefd20
$11 = 84
```
### Rat Holes
##### Careful not to mix frames!
When debugging, it is important to be aware of what frame you are in. I created a rat hole by mixing frames.  This is how I went down the rat hole:

I was running in the `main frame`:
```
p/x $rbp - 0x100
$5 = 0x7fffffffe410
```
I then used the same shortcut.  But I was inside another `frame`:
```
p/x $rbp - 0x100
0x7fffffffe300
```

##### Special characters
Any of the following characters in a memory address could cause a C API to choke when it tried to write to the address:

    - \x00 (Null)
    - \x09 (Tab)
    - \x0a (New line)
    - \x0d (Carriage return)
    - \x20 (Space)

#### GEF commands
```
gef> shellcode search linux arm
gef> shellcode get 698
[+] Downloading shellcode id=698
[+] Shellcode written to '/tmp/sc-fd1r2cvr.txt'

gef> vmmap
Start      End        Offset     Perm Path
0x00010000 0x00011000 0x00000000 r-x /opt/phoenix/arm/stack-four
0x00020000 0x00021000 0x00000000 rwx /opt/phoenix/arm/stack-four
0xf7752000 0xf77df000 0x00000000 r-x /opt/phoenix/arm-linux-musleabihf/lib/libc.so
0xf77ee000 0xf77ef000 0x0008c000 rwx /opt/phoenix/arm-linux-musleabihf/lib/libc.so
0xf77ef000 0xf77f1000 0x00000000 rwx
0xfffcf000 0xffff0000 0x00000000 rwx [stack]
0xffff0000 0xffff1000 0x00000000 r-x [vectors]



gef> check
checkpoint  checksec    
gef> checksec
[+] checksec for '/opt/phoenix/arm/stack-four'
Canary                        : No
NX                            : No
PIE                           : No
Fortify                       : No
RelRO                         : No


gef> xinfo 0xfffcf000
────────────────────────────── xinfo: 0xfffcf000 ──────────────────────────────
Page: 0xfffcf000  →  0xffff0000 (size=0x21000)
Permissions: rwx
Pathname: [stack]
Offset (from page): 0x0
Inode: 0
```

### Shell
##### Get a shell
`gdb) shell`
##### List files in present working directory
`gdb) shell ls`
##### Cat a file
`gdb) shell cat payload.txt`
##### Playing
`gdb) shell echo "hello there" | sed "s/hello/hi/" | sed "s/there/robots/"`
##### Drop into shell
`gef> shell`
##### Back to gdb
$ exit`
##### What type of shell
`# find -L /bin -samefile /bin/sh`
##### Bash is not the default shell for Ubuntu
https://stackoverflow.com/questions/2462317/bash-syntax-error-redirection-unexpected


### Cool commands
##### what is the current instruction
`where`
##### Set architecture to 32 bit Intel machine
`set architecture i386`
##### Set architecture to Auto
`set architecture auto`
##### disable ASLR in host machine
`sysctl -w kernel.randomize_va_space=0`   // whoami=root
##### disable ASLR
`gef➤  set disable-aslr`
##### Follow process forking
`set follow-fork-mode {parent, child, ask}`
#### Setup on macOS
```
https://timnash.co.uk/getting-gdb-to-semi-reliably-work-on-mojave-macos/

// NO `brew install gdb`
// NO `set startup-with-shell enable` inside of ~/.gdbinit

Create an Entitlements file

Create a Signing Certificate in KeyChain

codesign --entitlements gdb.xml -fs gdbcert /usr/local/bin/gdb
```
#### References
```
https://github.com/AnasAboureada/Penetration-Testing-Study-Notes/blob/master/cheatSheets/Cheatsheet_GDB.txt
https://www.exploit-db.com/papers/13205
https://sourceware.org/gdb/onlinedocs/gdb/Symbols.html
https://darkdust.net/files/GDB%20Cheat%20Sheet.pdf
https://blogs.oracle.com/linux/8-gdb-tricks-you-should-know-v2
```
