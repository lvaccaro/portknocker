PORT KNOCKER SERVER
autore: Mattia Cafagna
progetto per il corso di: Sistemi di elaborazione dell'informazione

Il server effettua il servizio di port knocking sulle porte locali del dispositivo di rete (predefinito eth0).
Il knock è inteso come tentativo di connessione da parte di un client ad una determinata porta.
Il procedimento si basa su sequenze di knock effettuate da un client su porte differenti in una determinato ordine.
Il server in presenza di una combinazione di knock corretta apre una porta (default 25) in entrata per lo specifico client, 
cosi' da permettare l'instaurazione di una connessione. A fine connessione una differente sequenza di knock permette di richiudere la porta.
Il client effettua solo dei tentativi di connessione in sequenza. Si possono usare altri comandi, quali telnet.
Per il corretto funzionamento e' necessario che il client e il server siano su due macchine distinte connesse alla rete. 

Impostazioni di default:
- dispositivo di rete predefinito: eth0
- porta sulla quale applicare i meccanismi di sicurezza: 22
- sequenza di porte per l'apertura: 1000, 2000, 3000
- sequenza di porte per la chiusura: 4000, 5000, 6000

Procedimento:

1. Comando per la compilazione:
gcc server.c -o server -lpcap
gcc client.c -o client

2. Eseguire il server:
sudo ./server

3. Effettuare le connessioni sul server:
./client <server_ip> <port1> <port2> ...
- aprire la porta sul server:   ./client 1000 2000 3000
- chiudere la porta sul server: ./client 4000 5000 6000

4. Comando per visualizzare le regole in iptables:
iptables -L
