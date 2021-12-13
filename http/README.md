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
