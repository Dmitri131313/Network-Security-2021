# Network Security 2021

Progetto per l'esame di Network Security A.A. 2021-2022
Gruppo Pisano-Poziello-Ruggiero

## Il framework Metasploit e applicazioni

Il __Metasploit Project__ è un progetto di sicurezza informatica che si propone di offrire informazioni circa le vulnerabilità di sicurezza e di aiutare nel penetration testing. Il sottoprogetto __Metasploit Framework__, che è quello che andremo ad utilizzare in questo lavoro, è uno strumento pensato per lo sviluppo ed esecuzione di _exploit_ verso una macchina remota target. Nel framework sono inoltre inclusi un database di payloads e dei tool di assistenza allo sviluppo degli attacchi.
Negli ultimi anni il progetto Metasploit si è rivelato essere lo standard de facto per lo sviluppo degli exploit, e pertanto ha guadagnato molto supporto dalla comunità della sicurezza, che ha contribuito con moduli che evidenziano le vulnerabilità di un particolare bug.

Gli step di base per l'utilizzo del framework sono i seguenti:

1. (Opzionale) Controllo delle vulnerabilità sul sistema target.
2. Scelta e configurazione di un particolare exploit, che in questo contesto sottende codice che verrà iniettato nella macchina target per mezzo di una particolare vulnerabilità, di default sono presenti più di 2000 exploit per tutti i principali sistemi operativi.
3. Scelta e configurazione di un _payload_ , codice che verrà eseguito sulla macchina target in seguito alla riuscita dell'exploit, esempi tipici sono l'esecuzione di una shell o di un server VNC.
4. Scelta della tecnica di encoding degli opcode esadecimali al fine di garantire la riuscita dell'exploit.
5. Esecuzione dell'exploit

Questa granularità nella scelta di combinazioni tra payloads è uno dei principali punti di forza di Metasploit. Il framework è interamente scritto in Ruby e esegue su qualunque macchina *nix (ad esempio MacOS, OpenBSD e Linux). 
Uno dei passaggi principali è la scelta del particolare exploit, per fare ciò è importante ottenere informazioni sulla macchina target. A tale scopo si utilizzano spesso tool di scanning e fingerprinting quali Nmap. Inoltre è possibile importare nel framework i risulati di alcuni dei più noti vulnerability scanners, come Nessus e OpenVAS.

## Installazione

Il framework è installato di default su tutte le distribuzioni kali linux, che è poi l'ambiente (virtualizzato) che utilizzeremo per i nostri test, ma nel caso si voglia installare manualmente di seguito sono elencati i comandi per MacOS/Linux.

```
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

Dopo l'installazione si può lanciare il programma con il comando ` /opt/metasploit-framework/bin/msfconsole ` che nella sua prima esecuzione permetterà di inserire il percorso nella variabile PATH locale.

## Metasploitable

Una volta settato l'ambiente d'attacco è il momento di cercare qualcosa da attaccare! E' però bene rendersi conto che Metasploit ha delle potenzialità enormi e con esse anche enormi potenzialità di creare danni, è perciò bene utilizzare Metasploit, specialmente per fini didattici, in una rete chiusa e con una macchina target fantoccio. A questo scopo viene in nostro aiuto lo stesso team Rapid7, che fornisce la macchina virtuale __Metasploitable__ che, come suggerisce il nome, è una macchina intenzionalmente vulnerabile e che spone una vasta gamma di servizi sulla rete.
Metasploitable è una macchina virtuale VMware ottenibile su [SourceForge](https://sourceforge.net/projects/metasploitable/).

## Definizione dell'ambiente d'attacco

L'ambiente in cui condurremo i nostri test sarà un ambiente virtualizzato. Metasploit eseguirà su una macchina kali ottenuta a partire dalla ultima [ISO stabile](https://www.kali.org/get-kali/). La configurazione di rete sarà di tipo host-only. In questo tipo di configurazione la VM non utlizza la scheda di rete dell'host, bensì una scheda di rete virtuale creata ad hoc da VirtualBox (o da qualunque software di virtualizzazione). Questa scheda di rete virtuale permette la connessione tra sistema host e VM, inoltre permette la comunicazione tra VM. Questa scheda di rete virtuale fornisce anche la funzionalità di server DHCP, andando ad assegnare gli indirizzi ai vari endpoint della rete. In questa configurazione i sistemi guest non potranno quindi accedere all'esterno e quindi alla rete internet, ma possono comunicare tra di loro, che è proprio il comportamento auspicabile ai nostri scopi. 
Vediamo velocemente come configurare la rete.

- Selezionare __Host-only Adapter__ nella sezione __Network__ delle opzioni della VM 

<!-- ![Network settings](/imgs/network_settings.png) -->
<img src="/imgs/network_settings.png" width="600"> </br>

- Nel caso non vi siano delle schede di rete virtuali nel menù a tendina precedenti bisogna andare a creare la scheda di rete dalle impostazioni. In VirtualBox andare in File->Host Network Manager, nel menù che si aprirà andare nella sezione Network, tab Host-only Networks, premere quindi l'icona con il simbolo +. Nello stesso menù si potrà inoltre andare a configurare le impostazioni dell'adapter, in particolare default gateway IP, maschera di sottorete, IP del server DHCP, range di indirizzi da assegnare. 

<!-- ![Network adapter](/imgs/network_adapter.png) -->
<img src="/imgs/network_adapter.png" width="600"> </br>

A questo punto una volta configurata la VM kali per verificare che la rete sia configurata in maniera appropriata basta lanciare il comando `ifconfig` e accertarsi che l'indirizzo ip dell'interfaccia _eth0_ sia del tipo `192.168.xxx.xxx`


<!-- ![ifconfig](/imgs/ifconfig.png) -->
<img src="/imgs/ifconfig.png" width="600"> </br>


In maniera simile configuriamo la rete dell macchina Metasploitable e la avviamo, si presenta quindi così:

<!-- ![metasploitable](/imgs/metasploitable.png) -->
<img src="/imgs/metasploitable.png" width="600"> </br>

Verifichiamo la presenza della macchina sulla rete locale dell'attaccante kali con il seguente comando `nmap`


```
nmap -sn -T5 192.168.56.0/24 | grep for | cut -d " " -f5
```

Vediamo il significato delle opzioni:

- __sn__: ping sweep, tecnica di base per la mappatura di una rete che consiste nell'invio di messaggi ping ICMP ad un range di indirizzi.
- __T5__: opzione di timing, il 5 indica la scelta di una mappatura più veloce possibile.

<!-- ![nmap](/imgs/nmap.png) -->
<img src="/imgs/nmap.png" width="600"> </br>

Da queso output determiniamo che la macchina target ha indirizzo `192.168.56.102`, dato che l'indirizzo 101 è la macchina locale, l'indirizzo 100 è il server DHCP e l'indirizzo 1 è la macchina host. a questo punto possiamo iniziare una fase di port scanning sulla macchina metasploitable con il comando

```
nmap 192.168.56.102 -v --open --reason -p-
```

- __v__: modalità verbosa.
- __open__: Cerco solo porte attive, non quelle ad esempio chiuse o filtrate.
- __reason__: Mostra la ragione per cui nmap ha determinato lo stato della porta.
- __p-__: Scansione di tutte le porte.

L'output del comando è il seguente:

```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-05 15:50 EST
Initiating Ping Scan at 15:50
Scanning 192.168.56.102 [2 ports]
Completed Ping Scan at 15:50, 0.00s elapsed (1 total hosts)
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Initiating Connect Scan at 15:50
Scanning 192.168.56.102 [65535 ports]

[...]

PORT      STATE SERVICE      REASON
21/tcp    open  ftp          syn-ack
22/tcp    open  ssh          syn-ack
23/tcp    open  telnet       syn-ack
25/tcp    open  smtp         syn-ack
53/tcp    open  domain       syn-ack
80/tcp    open  http         syn-ack
111/tcp   open  rpcbind      syn-ack
139/tcp   open  netbios-ssn  syn-ack
445/tcp   open  microsoft-ds syn-ack
512/tcp   open  exec         syn-ack
513/tcp   open  login        syn-ack
514/tcp   open  shell        syn-ack
1099/tcp  open  rmiregistry  syn-ack
1524/tcp  open  ingreslock   syn-ack
2049/tcp  open  nfs          syn-ack
2121/tcp  open  ccproxy-ftp  syn-ack
3306/tcp  open  mysql        syn-ack
3632/tcp  open  distccd      syn-ack
5432/tcp  open  postgresql   syn-ack
5900/tcp  open  vnc          syn-ack
6000/tcp  open  X11          syn-ack
6667/tcp  open  irc          syn-ack
6697/tcp  open  ircs-u       syn-ack
8009/tcp  open  ajp13        syn-ack
8180/tcp  open  unknown      syn-ack
8787/tcp  open  msgsrvr      syn-ack
38712/tcp open  unknown      syn-ack
39328/tcp open  unknown      syn-ack
48903/tcp open  unknown      syn-ack
56957/tcp open  unknown      syn-ack

[...]

```

Queste informazioni ci sono sicuramente molto utili, ma a questo punto andiamo ancora più nel dettaglio andando a fare enumeration su ogni singola porta aperta

```
nmap 192.168.XXX.XXX -v -sV -sC -p 21,22,23,25,53,80,111,139,445,512,513,514,1099,1524,2049,2121,3306,3632,5432,5900,6000,6667,6697,8009,8180,8787,36944,38918,54477,58406
```

- __sV__: Effettua il banner grabbing.
- __sC__: Utilizza il set di script di default per fare enumeration.

```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-05 15:58 EST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.

[...]

PORT      STATE  SERVICE     VERSION
21/tcp    open   ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.56.101
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp    open   ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
23/tcp    open   telnet      Linux telnetd
25/tcp    open   smtp        Postfix smtpd
|_smtp-commands: metasploitable.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
| ssl-cert: Subject: commonName=ubuntu804-base.localdomain/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Issuer: commonName=ubuntu804-base.localdomain/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2010-03-17T14:07:45
| Not valid after:  2010-04-16T14:07:45
| MD5:   dcd9 ad90 6c8f 2f73 74af 383b 2540 8828
|_SHA-1: ed09 3088 7066 03bf d5dc 2373 99b4 98da 2d4d 31c6
|_ssl-date: 2021-12-05T20:32:36+00:00; -25m48s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|_    SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
53/tcp    open   domain      ISC BIND 9.4.2
| dns-nsid: 
|_  bind.version: 9.4.2
80/tcp    open   http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.8 (Ubuntu) DAV/2
|_http-title: Metasploitable2 - Linux
111/tcp   open   rpcbind     2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/udp   nfs
|   100005  1,2,3      35803/udp   mountd
|   100005  1,2,3      38712/tcp   mountd
|   100021  1,3,4      38316/udp   nlockmgr
|   100021  1,3,4      56957/tcp   nlockmgr
|   100024  1          39328/tcp   status
|_  100024  1          40046/udp   status
139/tcp   open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open   netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
512/tcp   open   exec        netkit-rsh rexecd
513/tcp   open   login       OpenBSD or Solaris rlogind
514/tcp   open   shell       Netkit rshd
1099/tcp  open   java-rmi    GNU Classpath grmiregistry
1524/tcp  open   bindshell   Metasploitable root shell
2049/tcp  open   nfs         2-4 (RPC #100003)
2121/tcp  open   ftp         ProFTPD 1.3.1
3306/tcp  open   mysql       MySQL 5.0.51a-3ubuntu5
| mysql-info: 
|   Protocol: 10
|   Version: 5.0.51a-3ubuntu5
|   Thread ID: 10
|   Capabilities flags: 43564
|   Some Capabilities: Speaks41ProtocolNew, SupportsTransactions, ConnectWithDatabase, SwitchToSSLAfterHandshake, Support41Auth, LongColumnFlag, SupportsCompression
|   Status: Autocommit
|_  Salt: 0YQh9"=LF[vbh`-\ht01
3632/tcp  open   distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
5432/tcp  open   postgresql  PostgreSQL DB 8.3.0 - 8.3.7
| ssl-cert: Subject: commonName=ubuntu804-base.localdomain/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Issuer: commonName=ubuntu804-base.localdomain/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2010-03-17T14:07:45
| Not valid after:  2010-04-16T14:07:45
| MD5:   dcd9 ad90 6c8f 2f73 74af 383b 2540 8828
|_SHA-1: ed09 3088 7066 03bf d5dc 2373 99b4 98da 2d4d 31c6
|_ssl-date: 2021-12-05T20:32:36+00:00; -25m48s from scanner time.
5900/tcp  open   vnc         VNC (protocol 3.3)
| vnc-info: 
|   Protocol version: 3.3
|   Security types: 
|_    VNC Authentication (2)
6000/tcp  open   X11         (access denied)
6667/tcp  open   irc         UnrealIRCd
6697/tcp  open   irc         UnrealIRCd
8009/tcp  open   ajp13       Apache Jserv (Protocol v1.3)
|_ajp-methods: Failed to get a valid response for the OPTION request
8180/tcp  open   http        Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/5.5
8787/tcp  open   drb         Ruby DRb RMI (Ruby 1.8; path /usr/lib/ruby/1.8/drb)
36944/tcp closed unknown
38918/tcp closed unknown
54477/tcp closed unknown
58406/tcp closed unknown
MAC Address: 08:00:27:2B:A5:D0 (Oracle VirtualBox virtual NIC)
Service Info: Hosts:  metasploitable.localdomain, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 49m12s, deviation: 2h30m00s, median: -25m48s
| nbstat: NetBIOS name: METASPLOITABLE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   METASPLOITABLE<00>   Flags: <unique><active>
|   METASPLOITABLE<03>   Flags: <unique><active>
|   METASPLOITABLE<20>   Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|_  WORKGROUP<1e>        Flags: <group><active>
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: metasploitable
|   NetBIOS computer name: 
|   Domain name: localdomain
|   FQDN: metasploitable.localdomain
|_  System time: 2021-12-05T15:32:28-05:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

[...]

```

Ci viene dunque presentata una lista di servizi aperti corredata dalla loro versione e da tutte le altre informazioni che nmap è riuscito a racimolare tramite i suoi script di enumeration di default.

## Lista degli attacchi
