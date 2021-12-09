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

Questa granularità nella scelta di combinazioni tra payloads è uno dei principali punti di forza di Metasploit. Il framework è interamente scritto in Ruby e esegue su qualunque macchina \*nix (ad esempio MacOS, OpenBSD e Linux). 
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

Come il terminale suggerisce possiamo fare un login di default con le credenziali msfadmin/msfadmin, ma questo per il momento non è necessario. Verifichiamo la presenza della macchina sulla rete locale dell'attaccante kali con il seguente comando `nmap`


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

Queste informazioni ci sono sicuramente molto utili e sono la base sulla quale andremo a fare l'enumeration e il vulnerability scanning. Lo strumento che utilizzeremo è sempre nmap, in particolare l'Nmap Scripting Engine (NSE), strumento molto potente che permette agli utenti di scrivere degli script in Lua per automatizzare una vasta gamma di attività. Andremo però a lanciare questi script direttamente all'interno di Metasploit, per poter sfruttare il database integrato e salvare automaticamente gli output. Vediamo quindi velocemente come configurare e avviare Metasploit sulla nostra macchina kali.

Per prima cosa avviamo __msfbd__, utility integrata nel framework che utilizza un database __PostgreSQL__ per conservare e tenere traccia dei risultati ottenuti, importare ed esportare dati da tool esterni e di conservare le opzioni settate per i vari moduli.

```
systemctl start postgresql 

systemctl enable postgresql 

msfdb init
```

Una volta lanciati questi comandi avremo generato il database e a questo punto non ci resta che lanciare la console di Metasploit con il comando `msfconsole`, quello che ci troviamo davanti è un banner casuale tra i tanti disponibili, una breve lista di info sulla nostra installazione di Metasploit, come ad esempio la versione, il numero di exploit, ecc..., ed infine il prompt dei comandi.


<img src="/imgs/msfconsole.png" width="600"> </br>

Con il seguente comando andiamo quindi a lanciare gli script di default di nmap per fare enumeration su ogni singola porta aperta della macchina target.

```
msf6 > db_nmap -v --script vuln -p 21,22,23,25,53,80,111,139,445,512,513,514,1099,1524,2049,2121,3306,3632,5432,5900,6000,6667,6697,8009,8180,8787,36944,38918,54477,58406 192.168.56.102
[*] Nmap: Starting Nmap 7.91 ( https://nmap.org ) at 2021-12-09 17:43 EST
[*] Nmap: NSE: Loaded 105 scripts for scanning.
[*] Nmap: NSE: Script Pre-scanning.
[*] Nmap: Initiating NSE at 17:43
[*] Nmap: Completed NSE at 17:43, 0.00s elapsed
[*] Nmap: Initiating NSE at 17:43
[*] Nmap: Completed NSE at 17:43, 0.00s elapsed
[*] Nmap: Initiating ARP Ping Scan at 17:43
[*] Nmap: Scanning 192.168.56.102 [1 port]
[*] Nmap: Completed NSE at 17:49, 312.68s elapsed
[*] Nmap: Initiating NSE at 17:49
[*] Nmap: Completed NSE at 17:49, 0.58s elapsed
[*] Nmap: Nmap scan report for 192.168.56.102
[*] Nmap: Host is up (0.0010s latency).

[...]

[*] Nmap: PORT      STATE  SERVICE
[*] Nmap: 21/tcp    open   ftp
[*] Nmap: | ftp-vsftpd-backdoor:
[*] Nmap: |   VULNERABLE:
[*] Nmap: |   vsFTPd version 2.3.4 backdoor
[*] Nmap: |     State: VULNERABLE (Exploitable)
[*] Nmap: |     IDs:  BID:48539  CVE:CVE-2011-2523
[*] Nmap: |       vsFTPd version 2.3.4 backdoor, this was reported on 2011-07-04.
[*] Nmap: |     Disclosure date: 2011-07-03
[*] Nmap: |     Exploit results:
[*] Nmap: |       Shell command: id
[*] Nmap: |       Results: uid=0(root) gid=0(root)
[*] Nmap: |     References:
[*] Nmap: |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523
[*] Nmap: |       https://www.securityfocus.com/bid/48539
[*] Nmap: |       https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb
[*] Nmap: |_      http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html
[*] Nmap: |_sslv2-drown:
[*] Nmap: 22/tcp    open   ssh
[*] Nmap: 23/tcp    open   telnet
[*] Nmap: 25/tcp    open   smtp
[*] Nmap: | smtp-vuln-cve2010-4344:
[*] Nmap: |_  The SMTP server is not Exim: NOT VULNERABLE
[*] Nmap: | ssl-dh-params:
[*] Nmap: |   VULNERABLE:
[*] Nmap: |   Anonymous Diffie-Hellman Key Exchange MitM Vulnerability
[*] Nmap: |     State: VULNERABLE
[*] Nmap: |       Transport Layer Security (TLS) services that use anonymous
[*] Nmap: |       Diffie-Hellman key exchange only provide protection against passive
[*] Nmap: |       eavesdropping, and are vulnerable to active man-in-the-middle attacks
[*] Nmap: |       which could completely compromise the confidentiality and integrity
[*] Nmap: |       of any data exchanged over the resulting session.
[*] Nmap: |     Check results:
[*] Nmap: |       ANONYMOUS DH GROUP 1
[*] Nmap: |             Cipher Suite: TLS_DH_anon_WITH_AES_128_CBC_SHA
[*] Nmap: |             Modulus Type: Safe prime
[*] Nmap: |             Modulus Source: postfix builtin
[*] Nmap: |             Modulus Length: 1024
[*] Nmap: |             Generator Length: 8
[*] Nmap: |             Public Key Length: 1024
[*] Nmap: |     References:
[*] Nmap: |       https://www.ietf.org/rfc/rfc2246.txt
[*] Nmap: |
[*] Nmap: |   Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)
[*] Nmap: |     State: VULNERABLE
[*] Nmap: |     IDs:  BID:74733  CVE:CVE-2015-4000
[*] Nmap: |       The Transport Layer Security (TLS) protocol contains a flaw that is
[*] Nmap: |       triggered when handling Diffie-Hellman key exchanges defined with
[*] Nmap: |       the DHE_EXPORT cipher. This may allow a man-in-the-middle attacker
[*] Nmap: |       to downgrade the security of a TLS session to 512-bit export-grade
[*] Nmap: |       cryptography, which is significantly weaker, allowing the attacker
[*] Nmap: |       to more easily break the encryption and monitor or tamper with
[*] Nmap: |       the encrypted stream.
[*] Nmap: |     Disclosure date: 2015-5-19
[*] Nmap: |     Check results:
[*] Nmap: |       EXPORT-GRADE DH GROUP 1
[*] Nmap: |             Cipher Suite: TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
[*] Nmap: |             Modulus Type: Safe prime
[*] Nmap: |             Modulus Source: Unknown/Custom-generated
[*] Nmap: |             Modulus Length: 512
[*] Nmap: |             Generator Length: 8
[*] Nmap: |             Public Key Length: 512
[*] Nmap: |     References:
[*] Nmap: |       https://weakdh.org
[*] Nmap: |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4000
[*] Nmap: |       https://www.securityfocus.com/bid/74733
[*] Nmap: |
[*] Nmap: |   Diffie-Hellman Key Exchange Insufficient Group Strength
[*] Nmap: |     State: VULNERABLE
[*] Nmap: |       Transport Layer Security (TLS) services that use Diffie-Hellman groups
[*] Nmap: |       of insufficient strength, especially those using one of a few commonly
[*] Nmap: |       shared groups, may be susceptible to passive eavesdropping attacks.
[*] Nmap: |     Check results:
[*] Nmap: |       WEAK DH GROUP 1
[*] Nmap: |             Cipher Suite: TLS_DHE_RSA_WITH_DES_CBC_SHA
[*] Nmap: |             Modulus Type: Safe prime
[*] Nmap: |             Modulus Source: postfix builtin
[*] Nmap: |             Modulus Length: 1024
[*] Nmap: |             Generator Length: 8
[*] Nmap: |             Public Key Length: 1024
[*] Nmap: |     References:
[*] Nmap: |_      https://weakdh.org
[*] Nmap: | ssl-poodle:
[*] Nmap: |   VULNERABLE:
[*] Nmap: |   SSL POODLE information leak
[*] Nmap: |     State: VULNERABLE
[*] Nmap: |     IDs:  BID:70574  CVE:CVE-2014-3566
[*] Nmap: |           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
[*] Nmap: |           products, uses nondeterministic CBC padding, which makes it easier
[*] Nmap: |           for man-in-the-middle attackers to obtain cleartext data via a
[*] Nmap: |           padding-oracle attack, aka the "POODLE" issue.
[*] Nmap: |     Disclosure date: 2014-10-14
[*] Nmap: |     Check results:
[*] Nmap: |       TLS_RSA_WITH_AES_128_CBC_SHA
[*] Nmap: |     References:
[*] Nmap: |       https://www.imperialviolet.org/2014/10/14/poodle.html
[*] Nmap: |       https://www.securityfocus.com/bid/70574
[*] Nmap: |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
[*] Nmap: |_      https://www.openssl.org/~bodo/ssl-poodle.pdf
[*] Nmap: |_sslv2-drown: ERROR: Script execution failed (use -d to debug)
[*] Nmap: 53/tcp    open   domain
[*] Nmap: 80/tcp    open   http
[*] Nmap: | http-csrf:
[*] Nmap: | Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.56.102
[*] Nmap: |   Found the following possible CSRF vulnerabilities:
[*] Nmap: |
[*] Nmap: |     Path: http://192.168.56.102:80/dvwa/
[*] Nmap: |     Form id:
[*] Nmap: |     Form action: login.php
[*] Nmap: |
[*] Nmap: |     Path: http://192.168.56.102:80/dvwa/login.php
[*] Nmap: |     Form id:
[*] Nmap: |     Form action: login.php
[*] Nmap: |
[*] Nmap: |     Path: http://192.168.56.102:80/twiki/TWikiDocumentation.html
[*] Nmap: |     Form id:
[*] Nmap: |     Form action: http://TWiki.org/cgi-bin/passwd/TWiki/WebHome
[*] Nmap: |
[*] Nmap: |     Path: http://192.168.56.102:80/twiki/TWikiDocumentation.html
[*] Nmap: |     Form id:
[*] Nmap: |     Form action: http://TWiki.org/cgi-bin/passwd/Main/WebHome
[*] Nmap: |
[*] Nmap: |     Path: http://192.168.56.102:80/twiki/TWikiDocumentation.html
[*] Nmap: |     Form id:
[*] Nmap: |     Form action: http://TWiki.org/cgi-bin/edit/TWiki/
[*] Nmap: |
[*] Nmap: |     Path: http://192.168.56.102:80/twiki/TWikiDocumentation.html
[*] Nmap: |     Form id:
[*] Nmap: |     Form action: http://TWiki.org/cgi-bin/view/TWiki/TWikiSkins
[*] Nmap: |
[*] Nmap: |     Path: http://192.168.56.102:80/twiki/TWikiDocumentation.html
[*] Nmap: |     Form id:
[*] Nmap: |_    Form action: http://TWiki.org/cgi-bin/manage/TWiki/ManagingWebs
[*] Nmap: |_http-dombased-xss: Couldn't find any DOM based XSS.
[*] Nmap: | http-enum:
[*] Nmap: |   /tikiwiki/: Tikiwiki
[*] Nmap: |   /test/: Test page
[*] Nmap: |   /phpinfo.php: Possible information file
[*] Nmap: |   /phpMyAdmin/: phpMyAdmin
[*] Nmap: |   /doc/: Potentially interesting directory w/ listing on 'apache/2.2.8 (ubuntu) dav/2'
[*] Nmap: |   /icons/: Potentially interesting folder w/ directory listing
[*] Nmap: |_  /index/: Potentially interesting folder
[*] Nmap: | http-fileupload-exploiter:
[*] Nmap: |
[*] Nmap: |_    Couldn't find a file-type field.
[*] Nmap: | http-slowloris-check:
[*] Nmap: |   VULNERABLE:
[*] Nmap: |   Slowloris DOS attack
[*] Nmap: |     State: LIKELY VULNERABLE
[*] Nmap: |     IDs:  CVE:CVE-2007-6750
[*] Nmap: |       Slowloris tries to keep many connections to the target web server open and hold
[*] Nmap: |       them open as long as possible.  It accomplishes this by opening connections to
[*] Nmap: |       the target web server and sending a partial request. By doing so, it starves
[*] Nmap: |       the http server's resources causing Denial Of Service.
[*] Nmap: |
[*] Nmap: |     Disclosure date: 2009-09-17
[*] Nmap: |     References:
[*] Nmap: |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
[*] Nmap: |_      http://ha.ckers.org/slowloris/
[*] Nmap: | http-sql-injection:
[*] Nmap: |   Possible sqli for queries:
[*] Nmap: |     http://192.168.56.102:80/dav/?C=S%3bO%3dA%27%20OR%20sqlspider
[*] Nmap: |     http://192.168.56.102:80/dav/?C=D%3bO%3dA%27%20OR%20sqlspider
[*] Nmap: |     http://192.168.56.102:80/dav/?C=M%3bO%3dA%27%20OR%20sqlspider
[*] Nmap: |     http://192.168.56.102:80/dav/?C=N%3bO%3dD%27%20OR%20sqlspider
[*] Nmap: |     http://192.168.56.102:80/mutillidae/index.php?page=add-to-your-blog.php%27%20OR%20sqlspider

[... una lunga lista di outout derivanti dallo spidering 3-layer ...]

[*] Nmap: |[*] Nmap: |     http://192.168.56.102:80/dav/?C=D%3bO%3dA%27%20OR%20sqlspider
[*] Nmap: |_    http://192.168.56.102:80/dav/?C=N%3bO%3dA%27%20OR%20sqlspider
[*] Nmap: |_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
[*] Nmap: |_http-trace: TRACE is enabled
[*] Nmap: |_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
[*] Nmap: 111/tcp   open   rpcbind
[*] Nmap: 139/tcp   open   netbios-ssn
[*] Nmap: 445/tcp   open   microsoft-ds
[*] Nmap: 512/tcp   open   exec
[*] Nmap: 513/tcp   open   login
[*] Nmap: 514/tcp   open   shell
[*] Nmap: 1099/tcp  open   rmiregistry
[*] Nmap: | rmi-vuln-classloader:
[*] Nmap: |   VULNERABLE:
[*] Nmap: |   RMI registry default configuration remote code execution vulnerability
[*] Nmap: |     State: VULNERABLE
[*] Nmap: |       Default configuration of RMI registry allows loading classes from remote URLs which can lead to remote code execution.
[*] Nmap: |
[*] Nmap: |     References:
[*] Nmap: |_      https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/multi/misc/java_rmi_server.rb
[*] Nmap: 1524/tcp  open   ingreslock
[*] Nmap: 2049/tcp  open   nfs
[*] Nmap: 2121/tcp  open   ccproxy-ftp
[*] Nmap: 3306/tcp  open   mysql
[*] Nmap: |_ssl-ccs-injection: No reply from server (TIMEOUT)
[*] Nmap: |_sslv2-drown:
[*] Nmap: 3632/tcp  open   distccd
[*] Nmap: | distcc-cve2004-2687:
[*] Nmap: |   VULNERABLE:
[*] Nmap: |   distcc Daemon Command Execution
[*] Nmap: |     State: VULNERABLE (Exploitable)
[*] Nmap: |     IDs:  CVE:CVE-2004-2687
[*] Nmap: |     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
[*] Nmap: |       Allows executing of arbitrary commands on systems running distccd 3.1 and
[*] Nmap: |       earlier. The vulnerability is the consequence of weak service configuration.
[*] Nmap: |
[*] Nmap: |     Disclosure date: 2002-02-01
[*] Nmap: |     Extra information:
[*] Nmap: |
[*] Nmap: |     uid=1(daemon) gid=1(daemon) groups=1(daemon)
[*] Nmap: |
[*] Nmap: |     References:
[*] Nmap: |       https://nvd.nist.gov/vuln/detail/CVE-2004-2687
[*] Nmap: |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2687
[*] Nmap: |_      https://distcc.github.io/security.html
[*] Nmap: 5432/tcp  open   postgresql
[*] Nmap: | ssl-ccs-injection:
[*] Nmap: |   VULNERABLE:
[*] Nmap: |   SSL/TLS MITM vulnerability (CCS Injection)
[*] Nmap: |     State: VULNERABLE
[*] Nmap: |     Risk factor: High
[*] Nmap: |       OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
[*] Nmap: |       does not properly restrict processing of ChangeCipherSpec messages,
[*] Nmap: |       which allows man-in-the-middle attackers to trigger use of a zero
[*] Nmap: |       length master key in certain OpenSSL-to-OpenSSL communications, and
[*] Nmap: |       consequently hijack sessions or obtain sensitive information, via
[*] Nmap: |       a crafted TLS handshake, aka the "CCS Injection" vulnerability.
[*] Nmap: |
[*] Nmap: |     References:
[*] Nmap: |       http://www.openssl.org/news/secadv_20140605.txt
[*] Nmap: |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0224
[*] Nmap: |_      http://www.cvedetails.com/cve/2014-0224
[*] Nmap: | ssl-dh-params:
[*] Nmap: |   VULNERABLE:
[*] Nmap: |   Diffie-Hellman Key Exchange Insufficient Group Strength
[*] Nmap: |     State: VULNERABLE
[*] Nmap: |       Transport Layer Security (TLS) services that use Diffie-Hellman groups
[*] Nmap: |       of insufficient strength, especially those using one of a few commonly
[*] Nmap: |       shared groups, may be susceptible to passive eavesdropping attacks.
[*] Nmap: |     Check results:
[*] Nmap: |       WEAK DH GROUP 1
[*] Nmap: |             Cipher Suite: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
[*] Nmap: |             Modulus Type: Safe prime
[*] Nmap: |             Modulus Source: Unknown/Custom-generated
[*] Nmap: |             Modulus Length: 1024
[*] Nmap: |             Generator Length: 8
[*] Nmap: |             Public Key Length: 1024
[*] Nmap: |     References:
[*] Nmap: |_      https://weakdh.org
[*] Nmap: | ssl-poodle:
[*] Nmap: |   VULNERABLE:
[*] Nmap: |   SSL POODLE information leak
[*] Nmap: |     State: VULNERABLE
[*] Nmap: |     IDs:  BID:70574  CVE:CVE-2014-3566
[*] Nmap: |           The SSL protocol 3.0, as used in OpenSSL through 1.0.1i and other
[*] Nmap: |           products, uses nondeterministic CBC padding, which makes it easier
[*] Nmap: |           for man-in-the-middle attackers to obtain cleartext data via a
[*] Nmap: |           padding-oracle attack, aka the "POODLE" issue.
[*] Nmap: |     Disclosure date: 2014-10-14
[*] Nmap: |     Check results:
[*] Nmap: |       TLS_RSA_WITH_AES_128_CBC_SHA
[*] Nmap: |     References:
[*] Nmap: |       https://www.imperialviolet.org/2014/10/14/poodle.html
[*] Nmap: |       https://www.securityfocus.com/bid/70574
[*] Nmap: |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566
[*] Nmap: |_      https://www.openssl.org/~bodo/ssl-poodle.pdf
[*] Nmap: |_sslv2-drown:
[*] Nmap: 5900/tcp  open   vnc
[*] Nmap: |_sslv2-drown:
[*] Nmap: 6000/tcp  open   X11
[*] Nmap: 6667/tcp  open   irc
[*] Nmap: | irc-botnet-channels:
[*] Nmap: |_  ERROR: Closing Link: [192.168.56.101] (Too many unknown connections from your IP)
[*] Nmap: |_irc-unrealircd-backdoor: Looks like trojaned version of unrealircd. See http://seclists.org/fulldisclosure/2010/Jun/277
[*] Nmap: 6697/tcp  open   ircs-u
[*] Nmap: | irc-botnet-channels:
[*] Nmap: |_  ERROR: Closing Link: [192.168.56.101] (Too many unknown connections from your IP)
[*] Nmap: |_ssl-ccs-injection: No reply from server (TIMEOUT)
[*] Nmap: |_sslv2-drown:
[*] Nmap: 8009/tcp  open   ajp13
[*] Nmap: 8180/tcp  open   unknown
[*] Nmap: | http-cookie-flags:
[*] Nmap: |   /admin/:
[*] Nmap: |     JSESSIONID:
[*] Nmap: |       httponly flag not set
[*] Nmap: |   /admin/index.html:
[*] Nmap: |     JSESSIONID:
[*] Nmap: |       httponly flag not set
[*] Nmap: |   /admin/login.html:
[*] Nmap: |     JSESSIONID:
[*] Nmap: |       httponly flag not set
[*] Nmap: |   /admin/admin.html:
[*] Nmap: |     JSESSIONID:
[*] Nmap: |       httponly flag not set
[*] Nmap: |   /admin/account.html:
[*] Nmap: |     JSESSIONID:
[*] Nmap: |       httponly flag not set
[*] Nmap: |   /admin/admin_login.html:
[*] Nmap: |     JSESSIONID:
[*] Nmap: |       httponly flag not set
[*] Nmap: |   /admin/home.html:
[*] Nmap: |     JSESSIONID:
[*] Nmap: |       httponly flag not set
[*] Nmap: |   /admin/admin-login.html:
[*] Nmap: |     JSESSIONID:
[*] Nmap: |       httponly flag not set
[*] Nmap: |   /admin/adminLogin.html:

[...]

[*] Nmap: |       httponly flag not set
[*] Nmap: |   /admin/view/javascript/fckeditor/editor/filemanager/connectors/test.html:
[*] Nmap: |     JSESSIONID:
[*] Nmap: |       httponly flag not set
[*] Nmap: |   /admin/includes/FCKeditor/editor/filemanager/upload/test.html:
[*] Nmap: |     JSESSIONID:
[*] Nmap: |       httponly flag not set
[*] Nmap: |   /admin/jscript/upload.html:
[*] Nmap: |     JSESSIONID:
[*] Nmap: |_      httponly flag not set
[*] Nmap: | http-enum:
[*] Nmap: |   /admin/: Possible admin folder
[*] Nmap: |   /admin/index.html: Possible admin folder
[*] Nmap: |   /admin/login.html: Possible admin folder
[*] Nmap: |   /admin/admin.html: Possible admin folder

[...]

[*] Nmap: |   /admin/adminLogin.jsp: Possible admin folder
[*] Nmap: |   /manager/html/upload: Apache Tomcat (401 Unauthorized)
[*] Nmap: |   /manager/html: Apache Tomcat (401 Unauthorized)
[*] Nmap: |   /admin/view/javascript/fckeditor/editor/filemanager/connectors/test.html: OpenCart/FCKeditor File upload
[*] Nmap: |   /admin/includes/FCKeditor/editor/filemanager/upload/test.html: ASP Simple Blog / FCKeditor File Upload
[*] Nmap: |   /admin/jscript/upload.html: Lizard Cart/Remote File upload
[*] Nmap: |_  /webdav/: Potentially interesting folder
[*] Nmap: | http-slowloris-check:
[*] Nmap: |   VULNERABLE:
[*] Nmap: |   Slowloris DOS attack
[*] Nmap: |     State: LIKELY VULNERABLE
[*] Nmap: |     IDs:  CVE:CVE-2007-6750
[*] Nmap: |       Slowloris tries to keep many connections to the target web server open and hold
[*] Nmap: |       them open as long as possible.  It accomplishes this by opening connections to
[*] Nmap: |       the target web server and sending a partial request. By doing so, it starves
[*] Nmap: |       the http server's resources causing Denial Of Service.
[*] Nmap: |
[*] Nmap: |     Disclosure date: 2009-09-17
[*] Nmap: |     References:
[*] Nmap: |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
[*] Nmap: |_      http://ha.ckers.org/slowloris/
[*] Nmap: 8787/tcp  open   msgsrvr
[*] Nmap: 36944/tcp closed unknown
[*] Nmap: 38918/tcp closed unknown
[*] Nmap: 54477/tcp closed unknown
[*] Nmap: 58406/tcp closed unknown
[*] Nmap: MAC Address: 08:00:27:2B:A5:D0 (Oracle VirtualBox virtual NIC)
[*] Nmap: Host script results:
[*] Nmap: |_smb-vuln-ms10-054: false
[*] Nmap: |_smb-vuln-ms10-061: false
[*] Nmap: |_smb-vuln-regsvc-dos: ERROR: Script execution failed (use -d to debug)
[*] Nmap: NSE: Script Post-scanning.
[*] Nmap: Initiating NSE at 17:49
[*] Nmap: Completed NSE at 17:49, 0.00s elapsed
[*] Nmap: Initiating NSE at 17:49
[*] Nmap: Completed NSE at 17:49, 0.00s elapsed
[*] Nmap: Read data files from: /usr/bin/../share/nmap
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 314.01 seconds
[*] Nmap: Raw packets sent: 31 (1.348KB) | Rcvd: 31 (1.332KB)
```

Ci viene dunque presentata una lista di servizi aperti corredata dalla loro versione e da tutte le altre informazioni che nmap è riuscito a racimolare tramite i suoi script di enumeration di default.

## Lista degli attacchi

I link che seguono rimandano alle sezioni degli specifichi attacchi che abbiamo realizzato con Metasploit e documentato per questo progetto.

- [FTP](ftp/)
- [SSH](ssh/)
- [TELNET](telnet/)
- [SMTP](smtp/)
- [HTTP](http/)
