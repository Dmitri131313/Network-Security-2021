# FTP

In questa sezione andremo a realizzare un attacco sul servizio FTP, in particolare sfrutteremo una vulnerabilità molto nota relativa al server FTP vsftpd (acronimo di Very Secure FTP Daemon n.d.r.), daemon molto utilizzato nei sistemi *nix. In realtà questa vulnerabilità non deriva da un bug nel codice, bensì dalla compromissione del sito web ufficiale sul quale un attaccante ha caricato una versione del programma compilato con una backdoor che permette, facendo login con uno smile ":)" di ottenere una bind shell sulla porta 6200. Sebbene questa compromissione fu scoperta molto velocemente, un gran numero di persone ha comunque scaricato questa versione del software (v2.3.4).

Riprendendo l'output dell'enumeration effettuata in precedenza sulla macchina target notiamo che la versione installata di vsftpd è proprio quella incriminata ed è quindi molto probabile sia vulnerabile a questo exploit.

```
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
```

Possiamo attaccare il target in diversi modi, sul sito [exploit-db.com](exploit-db.com) troviamo ad esempio uno [script Pyhton](https://www.exploit-db.com/exploits/49757) che ci consente di ottenere automaticamente la shell, ma noi siamo interessati all'utilizzo di Metasploit ed è quindi questo il tool che andremo a sfruttare.

Vediamo quindi innanzitutto come configurare e avviare Metasploit sulla nostra macchina kali. Per prima cosa avviamo __msfbd__, utility integrata nel framework che utilizza un database __PostgreSQL__ per conservare e tenere traccia dei risultati ottenuti, importare ed esportare dati da tool esterni e di conservare le opzioni settate per i vari moduli.

```
systemctl start postgresql 

systemctl enable postgresql 

msfdb init
```

Una volta lanciati questi comandi avremo generato il database e a questo punto non ci resta che lanciare la console di Metasploit con il comando `msfconsole`, quello che ci troviamo davanti è un banner casuale tra i tanti disponibili, una breve lista di info sulla nostra installazione di Metasploit, come ad esempio la versione, il numero di exploit, ecc... ed infine il promp dei comandi.


<img src="/imgs/msfconsole.png" width="600"> </br>



