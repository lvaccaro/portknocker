// PORT KNOCKER SERVER
//autore: Mattia Cafagna

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <getopt.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

//Porta sulla quale applicare i meccanismi di sicurezza
#define PORT 22

//Numero massimo di client che effettuano il knock
#define MAXCLIENT 128

// Strutture
struct client{
	char    address[16]; //indirizzo del client
	int     count_knock_open;   //numero di knock corretti per l'apertura
	int     count_knock_close;  //numero di knock corretti per la chiusura
	char    port_status; //porta associata: aperta(1), chiusa(0)
};
typedef struct client Client;


// Variabili globali
char localip[]="000.000.000.000\0"; 		//indirizzo ip locale
int  SEQ_OPEN_PORTS [3]={1000, 2000, 3000};	//combinazione di knock per l'apertura
int  SEQ_CLOSE_PORTS[3]={4000, 5000, 6000};	//combinazione di knock per la chiusura
Client clientlist[MAXCLIENT]={0};		//lista dei client che effettuano il knock
int clientlist_size=0;				//dimensioni della lista

// Prototipi delle funzioni 
int get_localip		(void);			//prelevare l'ip locale
int get_packet		(pcap_t *pcap_fd);	//ottenere il pacchetto ricevuto
void sequence_port	(char *ipsrc, char *ipdst, int portsrc, int portdst); //controllare la sequenza di knock sulle porte
int open_port		(char *clientip);	//aprire la porta PORT verso le connessioni in entrata dal clientip (uso iptables)
int close_port		(char *clientip);	//chiudere la porta PORT verso le connessioni in entrata dal clientip (uso iptables)
int block_port		(void);			//blindare la porta PORT verso tutte le connessioni in entrata (uso iptables)
int unblock_port	(void);			//sblocca la porta PORT verso tutte le connessioni in entrata (uso iptables)


int main(void)
{
	char *pcap_device;		// dispositivo da sniffare
	char errbuf[PCAP_ERRBUF_SIZE];	// stringa di errore
	pcap_t *pcap_fd;		// descrittore della sessione
	struct bpf_program filter;	// filtro
	bpf_u_int32 netmask;            // netmask
	bpf_u_int32 netaddr;            // ip 


	//Blocco e chiudo la porta PORT verso tutte le connessioni in entrata a PORT
	block_port();

	//prelevo l'ip locale
	get_localip();

	//Inizializza il dispositivo di sniff: eth0 per default
	pcap_device = pcap_lookupdev(errbuf);
	pcap_lookupnet(pcap_device , &netaddr , &netmask , errbuf);
	pcap_fd=pcap_open_live(pcap_device, BUFSIZ, 1, 0, errbuf);
	//imposta il filtro sui pacchetti ip
	pcap_compile(pcap_fd, &filter, "ip", 0, netaddr);
	pcap_setfilter(pcap_fd, &filter);

	printf(" Start Sniffing...\n");

	while(1) {
		get_packet(pcap_fd);
	}

	pcap_close(pcap_fd);

	//Sblocco la porta PORT verso tutte le connessioni in entrata a PORT
	block_port();

	exit(0);
}

int get_packet(pcap_t *pcap_fd)
{
	const u_char *pcap_pkt;         // pacchetto attuale
	struct pcap_pkthdr pcap_hdr;    // header proveniente dalle pcap
	struct iphdr *ip;		// header ip 
	struct tcphdr *tcp;		// header tcp 

	int offset, datalink, portsrc,portdst;
	struct in_addr srcfd, dstfd;
	char ipsrc[16], ipdst[16];

	pcap_pkt = pcap_next(pcap_fd, &pcap_hdr);

	switch((datalink=pcap_datalink(pcap_fd))) {
		case DLT_EN10MB:
			offset = 14;
			break;
		case DLT_NULL:   
		case DLT_PPP:
			offset = 4;
			break;
		case DLT_SLIP:
			offset = 16;
			break;
		case DLT_RAW:
			offset = 0;
			break;
		case DLT_SLIP_BSDOS:
		case DLT_PPP_BSDOS:
			offset = 24;
			break;
		case DLT_PPP_ETHER:
			printf("PPPoE Not Supported.\n");
			exit(-1);   
		case 113:
			offset = 20;
			break;
		default:
			printf("unknown datalink type (%d)\n", datalink);
			return -1;
	}

	// controlla l'header del pacchetto ip
	ip= (struct iphdr *) (pcap_pkt + offset);
	srcfd.s_addr= ip->saddr;
	dstfd.s_addr= ip->daddr;
	strcpy(ipsrc,inet_ntop(AF_INET,&srcfd,ipsrc,sizeof(ipsrc)));
	strcpy(ipdst,inet_ntop(AF_INET,&dstfd,ipdst,sizeof(ipdst)));

	// controlla l'header del pacchetto tcp
	tcp = (struct tcphdr *)(pcap_pkt + offset + ip->ihl*4);
	portsrc=ntohs(tcp->source);
	portdst=ntohs(tcp->dest);

	//printf("[%s:%d]------(*)------>[%s:%d]\n",ipsrc,portsrc,ipdst,portdst);

	//controllo il pacchetto come sequenza di knocking
	sequence_port(ipsrc, ipdst, portsrc, portdst);
}

void sequence_port(char *ipsrc, char *ipdst, int portsrc, int portdst)
{

	// Compara destination ip and local ip
	if (strncmp(localip,ipdst,16)!=0)
		return;

	//Controlla se il client e' gia' conosciuto
	int i=0, found=0;
	while (i<clientlist_size && found==0){
		if( strncmp(clientlist[i].address,ipsrc,16)==0)
			found=1;
		else
			i++;
	}

	if (found==0){
		//il client non e' gia' conosciuto
		//aggiungo il client in fondo alla lista
		if (portdst!=SEQ_OPEN_PORTS[0] && portdst!=SEQ_CLOSE_PORTS[0])
			return;
		if(clientlist_size==MAXCLIENT){
			printf("(II) Out of memory\n");
			return;
		}
		i=clientlist_size;
		clientlist_size++;
		strcpy(clientlist[i].address,ipsrc);
		clientlist[i].port_status = 0;
		clientlist[i].count_knock_open  = 0;
		clientlist[i].count_knock_close = 0;
		if(portdst==SEQ_OPEN_PORTS[0]){
			clientlist[i].count_knock_open = 1;
			printf("(II) %s knock port %d: 1-time => add to the open list\n",ipsrc,portdst);
		}else if(portdst==SEQ_CLOSE_PORTS[0]){
			clientlist[i].count_knock_close = 1;
			printf("(II) %s knock port %d: 1-time => add to the close list\n",ipsrc,portdst);
		}
	}
	else
	{
		//il client e' gia' conosciuto
		if(portdst==SEQ_OPEN_PORTS[0] || portdst==SEQ_OPEN_PORTS[1] || portdst==SEQ_OPEN_PORTS[2]){
			// il client invia un knock sulla porta di apertura nella corretta combinazione
			// incremento il contatore port_open dell'elemento nella lista

			if (clientlist[i].port_status==1){
				printf("(II) %s port already open\n",ipsrc); //se era gia' aperta
			}else if (portdst==SEQ_OPEN_PORTS[0]){
				clientlist[i].count_knock_open=1;
				printf("(II) %s knock port %d: 1-time\n",ipsrc,portdst);
			}else if (clientlist[i].count_knock_open==1 && portdst==SEQ_OPEN_PORTS[1]){
				clientlist[i].count_knock_open=2;
				printf("(II) %s knock port %d: 2-time\n",ipsrc,portdst);
			}else if (clientlist[i].count_knock_open==2 && portdst==SEQ_OPEN_PORTS[2]){
				//apri la porta
				clientlist[i].count_knock_open=3;
				printf("(II) %s knock port %d: 3-time => open port\n",ipsrc,portdst);	
				clientlist[i].port_status=1;
				clientlist[i].count_knock_open=0;
				open_port(ipsrc);		
			}else
				;					
		}else if (portdst==SEQ_CLOSE_PORTS[0] || portdst==SEQ_CLOSE_PORTS[1] || portdst==SEQ_CLOSE_PORTS[2] ){
			// il client invia un knock sulla porta di chiusura nella corretta combinazione
			// incremento il contatore port_close dell'elemento nella lista

			if (clientlist[i].port_status==0){
				printf("(II) %s port already close\n",ipsrc); //se era gia' chiusa
			}else if (portdst==SEQ_CLOSE_PORTS[0]){
				clientlist[i].count_knock_close=1;
				printf("(II) %s knock port %d: 1-time\n",ipsrc,portdst);
			}else if (clientlist[i].count_knock_close==1 && portdst==SEQ_CLOSE_PORTS[1]){
				clientlist[i].count_knock_close=2;
				printf("(II) %s knock port %d: 2-time\n",ipsrc,portdst);
			}else if (clientlist[i].count_knock_close==2 && portdst==SEQ_CLOSE_PORTS[2]){
				//chiudi la porta
				clientlist[i].count_knock_close=3;
				printf("(II) %s knock port %d: 3-time => close port\n",ipsrc,portdst);
				clientlist[i].port_status=0;
				clientlist[i].count_knock_close=0;
				close_port(ipsrc);
			}else
				;
		}else {
			// il client invia un knock scorretto
			// azzera i volari dalla lista
			printf("(II) %s knock port %d: delete from the list\n",ipsrc,portdst);
			clientlist[i].count_knock_open=0;
			clientlist[i].count_knock_close=0;
		}
	}
}

int get_localip(void)
{
	char hostn[400];
	struct hostent *hostIP;

	if((gethostname(hostn, sizeof(hostn))) != 0)
		return -1;
	hostIP = gethostbyname(hostn); 
	sprintf(localip,"%s\0", inet_ntoa(*(struct in_addr*)hostIP->h_addr));

	return 0;
}

int block_port (void)
{
	int pid;
	printf("block %d port for all IP clients\n",PORT);
	pid=fork();
	if ( pid == 0 ){
		// Uso iptables per chiudere la porta PORT verso tutte le connessioni in entrata
		// inserisco una regola per bloccare le connessioni
		char flag_destip[20];
		char flag_destport[16];
		sprintf(flag_destport,"--dport=%d\0",PORT);
		sprintf(flag_destip,"-d%s\0",localip);

		execlp("/sbin/iptables","/sbin/iptables", "-AINPUT", "-ptcp", flag_destip,flag_destport, "-jDROP", NULL);
		exit(0);
	}
	return 1;
}

int unblock_port (void)
{
	int pid;
	printf("block %d port for all IP clients\n",PORT);
	pid=fork();
	if ( pid == 0 ){
		// Uso iptables per ripristinare la porta PORT verso tutte le connessioni in entrata
		// elimino la regola di blocco delle connessioni
		char flag_destip[20];
		char flag_destport[16];
		sprintf(flag_destport,"--dport=%d\0",PORT);
		sprintf(flag_destip,"-d%s\0",localip);

		execlp("/sbin/iptables","/sbin/iptables", "-DINPUT", "-ptcp", flag_destip,flag_destport, "-jDROP", NULL);
		exit(0);
	}
	return 1;
}


int close_port(char *clientip)
{
	int pid;
	printf("close %d port for IP %s client\n",PORT, clientip);
	pid=fork();
	if ( pid == 0 ){
		// Uso iptables per chiudere la porta PORT verso connessioni in entrata verso clientip
		// elimino la regola di accettazione relativa alla connessione
		char flag_destip[20], flag_sourceip[20];
		char flag_destport[16];
		sprintf(flag_destport,"--dport=%d",PORT);
		sprintf(flag_destip,"-d%s",localip);
		sprintf(flag_sourceip,"-s%s",clientip);

		execlp("/sbin/iptables","/sbin/iptables", "-DINPUT", "-ptcp", flag_sourceip, flag_destip,flag_destport, "-jACCEPT", NULL);
		exit(0);
	}
	return 1;
}



int open_port (char *clientip)
{
	int pid;
	printf("open %d port for IP client %s\n",PORT, clientip);
	pid=fork();
	if ( pid == 0 ){
		// Uso iptables per aprire la porta PORT verso connessioni in entrata verso clientip
		// inserisco una regola di accettazione relativa alla connessione
		char flag_destip[20], flag_sourceip[20];
		char flag_destport[16];
		sprintf(flag_destport,"--dport=%d",PORT);
		sprintf(flag_destip,"-d%s",localip);
		sprintf(flag_sourceip,"-s%s",clientip);

		execlp("/sbin/iptables","/sbin/iptables", "-AINPUT", "-ptcp", flag_sourceip, flag_destip,flag_destport, "-jACCEPT", NULL);
		exit(0);
	}
	return 1;
}
