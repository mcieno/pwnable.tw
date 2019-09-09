# cieno @ pwnable.tw

My solutions to [pwnable.tw](//pwnable.tw/) challenges. Solve them yourself before checking these out.

This collection is structured as follows.

```txt
├── XX-challenge-name
│   ├── files
│   │   ├── challenge-binary
│   │   └── ...
│   └── solve.py
└── ...
```

## Requirements

+ [pwntools](//docs.pwntools.com): CTF framework and exploit development library

## Usage

Solution to challenges are inside `XX-challenge-name/solve.py`.

Usage is very simple:

```
./solve.py {remote|locale} [test]
```

+ `remote`: run exploit remotely *(exploit the real challenge and get the flag)*
+ `locale`: run exploit locally *(no real flag)*
- `test`: test the challenge interactively, either locally or remotely *(no exploit, no flag)*

### Example

```sh
$ ./solve.py locale
[*] '/00-start/files/start'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './files/start': pid 16139
[+] Retrieving ESP: 0xffe17220
[+] Sending shellcode: Done
[*] Switching to interactive mode
$ ls
files  solve.py
```

```sh
$ ./solve.py remote
[*] '/00-start/files/start'
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to chall.pwnable.tw on port 10000: Done
[+] Retrieving ESP: 0xffbd3fd0
[+] Sending shellcode: Done
[*] Switching to interactive mode
$ cat /home/start/flag
<redacted>
```
