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

- Selezionare __Host-only Adapter__ nella sezione __Network__ delle opzioni della VM ![Network settings](/imgs/network_settings.png)

- Nel caso non vi siano delle schede di rete virtuali nel menù a tendina precedenti bisogna andare a creare la scheda di rete dalle impostazioni. In VirtualBox andare in File->Host Network Manager, nel menù che si aprirà andare nella sezione Network, tab Host-only Networks, premere quindi l'icona con il simbolo +. Nello stesso menù si potrà inoltre andare a configurare le impostazioni dell'adapter, in particolare default gateway IP, maschera di sottorete, IP del server DHCP, range di indirizzi da assegnare. ![Network adapter](/imgs/network_adapter.png)

A questo punto una volta configurata la VM kali per verificare che la rete sia configurata in maniera appropriata basta lanciare il comando `ifconfig` e accertarsi che l'indirizzo ip dell'interfaccia _eth0_ sia del tipo

> 192.168.xxx.xxx

![ifconfig](/imgs/ifconfig.png)

In maniera simile configuriamo la rete dell macchina Metasploitable e la avviamo, si presenta quindi così:

![metasploitable](/imgs/metasploitable.png)

Verifichiamo la presenza della macchina sulla rete locale dell'attaccante kali con il seguente comando `nmap`


```
nmap -sn -T5 192.168.xxx.0/24 | grep for | cut -d " " -f5
```

Vediamo il significato delle opzioni:

- __sn__: ping sweep, tecnica di base per la mappatura di una rete che consiste nell'invio di messaggi ping ICMP ad un range di indirizzi.
- __T5__: opzione di timing, il 5 indica la scelta di una mappatura più veloce possibile.

![nmap](/imgs/nmap.png)




## Lista degli attacchi
