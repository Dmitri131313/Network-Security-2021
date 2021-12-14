# Slowloris

Introduciamo in questa sezione un particolare attacco di tipo Denial of Service ad un web server. 

Un Denial of Service indica un attacco in cui si vanno ad esaurire le risorse di un sistema informatico che fornisce un servizio fino a renderlo completamente inutilizzabile dai client. Dunque, tale tipologia di attacco va a minare l'availability di un servizio. 

Una metodologia standard per andare ad intaccare l'availability di un web server con un attacco DoS è aprire quante più richieste e possibile verso di esso che andranno così a consumare tutte le risorse fino a rendere il server non più accessibile. 

Lo slowloris effettua un DoS in modo leggermente diverso, esso va a minare l'availability di un server utilizzando delle richieste http che sono appunto lente. 

In particolare, tale attacco cerca di mantenere quante più connessioni attive verso il web server target. Questo è possibile aprendo delle connessioni verso il target e inviando delle richieste parziali, periodicamente su tale connessione si va ad aggiungere qualcosa alla richiesta senza però mai portarla a termine. L'effetto di tutto ciò sarà che il server terrà aperte queste connessioni, andando a raggiungere la soglia di connessioni concorrenti e negandone di nuove da altri client. 

Possiamo accedere al nostro web server, che si trova sulla macchina metasploitable2, da un browser di ricerca e digitando l'indirizzo IP, da qui apriamo una pagina della Damn Vulnerable Web Application (DVWA). Tale web server sarà available e responsivo. 

<img src="/imgs/WebServer1.png" width="600"> </br>

Di seguito, l'interfacci di DVMA:

<img src="/imgs/DVMA.png" width="600"> </br>


Procediamo quindi all'attacco tramite metasploit.
