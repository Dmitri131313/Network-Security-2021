# Telnet
Telnet è uno dei primi protocolli di rete di tipo client server, il suo RFC risale al 1983, e si basa su TCP.
Scopo di tale protocollo è fornire una connesione bidirezionale e fornire un metodo standard di interfacciamento tra i vari device.

Relativamente alla sicurezza di tale protocollo vi sono tre problemi principali:
1. Manca uno schema di autenticazione che renda sicure e non intercettabili le comunicazioni tra i due host;
2. Tutti i dati, comprese le password, sono inviate in chiaro senza alcun tipo di cifratura;
3. Presenta ancora ad oggi all'interno del suo deamon delle vulnerabilità non coperte.

In questa sezione mostrermo come è possibile apirere una sessione telnet verso una macchina di cui conosciamo l'IP. Se sulla rete è presente uno sniffer, esso sarà in grado di intercettare tutti i pacchetti scambiati e di leggere in chiaro eventuali dati sensibili come user e password.

Dalla operazione di enumeration fatta preliminarmente, sappiamo che la macchina metasploitable 2 presenta il protocollo Telnet su uno dei suoi porti, andremo quindi a realizzare una connessione di questo tipo dalla nostra macchina kali verso di essa. 
Questo ci restituirà all'interno della shell l'accesso alla shell di metaspoloitable 2 come mostrato nella seguente sezione di codice:

``` 
┌──(francesco㉿kali)-[~]
└─$ telnet 192.168.198.4                                     
Trying 192.168.198.4...
Connected to 192.168.198.4.
Escape character is '^]'.
                _                  _       _ _        _     _      ____  
 _ __ ___   ___| |_ __ _ ___ _ __ | | ___ (_) |_ __ _| |__ | | ___|___ \ 
| '_ ` _ \ / _ \ __/ _` / __| '_ \| |/ _ \| | __/ _` | '_ \| |/ _ \ __) |
| | | | | |  __/ || (_| \__ \ |_) | | (_) | | || (_| | |_) | |  __// __/ 
|_| |_| |_|\___|\__\__,_|___/ .__/|_|\___/|_|\__\__,_|_.__/|_|\___|_____|
                            |_|                                          


Warning: Never expose this VM to an untrusted network!

Contact: msfdev[at]metasploit.com

Login with msfadmin/msfadmin to get started


metasploitable login: msfadmin
Password: 
Last login: Sat Dec 11 19:58:23 EST 2021 on tty1
Linux metasploitable 2.6.24-16-server #1 SMP Thu Apr 10 13:58:00 UTC 2008 i686

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/
No mail.
msfadmin@metasploitable:~$ 

```
Nella sessione appena aperta abbiamo effettuato un accesso con user e password alla macchina. Se sulla rete era attivo un tool di sniffing come wireshark possiamo osservare come l'intero traffico può essere non solo intercettato ma visualizzato in chiaro per la vulnerabilità offerta da tale protocollo.

<img src="/imgs/newTELNET.png" width="800"> </br>

Per sopperire tale vulnerabilità basta adottare un protcollo diverso da TELNET come SSH che va a utilizzare la crittografia sul messaggio trasmesso quindi la medesima operazione effettuata con il tool di sniffing porterà ad avere il seguente risultato.

<img src="/imgs/newSSH.png" width="800"> </br>
