#include	"hw_addrs.h"
#include    "unp.h"
#include    "common.h"
#include    <string.h>
#include    <linux/if_packet.h>
#include    <linux/if_ether.h>
#include    <linux/if_arp.h>

/* FUNCTION PROTOTYPES BEGIN HERE */
/* ****************************** */

void createIfList(void);
void addToIfList(char *, int, char *);
void printIfaces(void); 
void broadcastARPRequest(char *, int );
void sendARPReply(int, unsigned char *, int, char *);
void insertToARPCache(char *, char *, int, int, int);
void updateCache(char *, char *, int, int, int);
void lookupCache(char *, char *, int *, int *);
void printARPCache(void);
void deleteFromARPCache(char *);
char *findhostname(char *);

/* FUNCTION PROTOTYPES END HERE */
/* **************************** */



int main(int argc, char **argv)
{
    int listenfd_tour, connfd_tour, n, i, slen, pfsock_arp, t_ifindex, t_hatype;
    char sendtomac[18], recvline[MAXLINE], t_hwaddr[18], partialIP[16];
    char reqhost[100],rephost[100];
	struct hwaddr replyToTour;
    socklen_t clilen;
    struct sockaddr_un cliaddr, servaddr;
    struct sockaddr_ll saddr;
    struct s_arppkt *pkt_recd;
    struct s_ARP_cache *curr;
    void *buffer = (void *)malloc(ETH_FRAME_LEN);
	int flagBroadcasted = 0;
    strcpy(partialIP,"");
	
	//Declaration for Select
	fd_set rset;
	int maxfd;

    ifhead = NULL;
	ARP_cache_head = NULL;
    printf("ARP process started.\n");
    createIfList();
    printIfaces();

	pfsock_arp = Socket(PF_PACKET, SOCK_RAW, htons(USID_PROTO));
    listenfd_tour = Socket(AF_LOCAL, SOCK_STREAM, 0);

    unlink(ARP_PATH);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_LOCAL;
    strcpy(servaddr.sun_path, ARP_PATH);

    Bind(listenfd_tour, (SA *) &servaddr, sizeof(servaddr));
    Listen(listenfd_tour, LISTENQ);

	
	for(;;)
    {
        FD_ZERO(&rset);
        FD_SET(listenfd_tour,&rset); //For other ARPs
        FD_SET(pfsock_arp,&rset);
		if( flagBroadcasted == 1)
		{
			FD_SET(connfd_tour,&rset);
			maxfd = max(listenfd_tour, max(pfsock_arp, connfd_tour)) + 1;
		}
		else
			maxfd = max(listenfd_tour,pfsock_arp) + 1;

        if( (select(maxfd,&rset,NULL,NULL,NULL)) < 0)
		{
			if(errno == EINTR)
                continue;
            else
            {
                printf("Error in select, errno : %s ! Exitting the program\n",strerror(errno));
                exit(-1);
            }
		}
		
		// ARP request from tour
		if(FD_ISSET(listenfd_tour,&rset))
		{
			clilen = sizeof(cliaddr);
			if ( (connfd_tour = accept(listenfd_tour, (SA *) &cliaddr, &clilen)) < 0) {
					printf("Accept error, quitting!\n");
					exit(-1);
			}
			flagBroadcasted	= 1;
		}
		else if(FD_ISSET(connfd_tour,&rset))
		{
			if( (n = recv(connfd_tour, (char *)recvline, MAXLINE, 0)) <= 0 )
			{
                #ifdef DEBUG
				printf("Tour has ended\n");
                #endif
                for(curr = ARP_cache_head; curr != NULL; curr = curr->next)
                    deleteFromARPCache(partialIP);
                
				flagBroadcasted = 0;
                strcpy(partialIP,"");
				close(connfd_tour);
				continue;
			}
			recvline[n] = 0 ; 
            #ifdef DEBUG
			printf("Received from tour: %s\n",recvline);
            #endif
            strcpy(partialIP, recvline);
			
			lookupCache(recvline, t_hwaddr, &t_ifindex, &t_hatype);
            #ifdef DEBUG
				printf("Lookup of ARP Cache, found : %s, %s\n", recvline, t_hwaddr);
			#endif

			if( strcmp(t_hwaddr, "") == 0 )
			{
				//Need to find MAC address for IP in recvline
				#ifdef DEBUG
					printf("Entry not available in cache, broadcast required\n");
				#endif
				broadcastARPRequest(recvline, pfsock_arp);
			}
			else
			{
                    replyToTour.sll_ifindex = t_ifindex;
                    replyToTour.sll_hatype = t_hatype;
                    replyToTour.sll_halen = sizeof(t_hatype);
                    sscanf(t_hwaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                            &replyToTour.sll_addr[0],&replyToTour.sll_addr[1],&replyToTour.sll_addr[2],&replyToTour.sll_addr[3],
                            &replyToTour.sll_addr[4],&replyToTour.sll_addr[5]);
                    replyToTour.sll_addr[6] = 0;
                    replyToTour.sll_addr[7] = 0;

					printf("ARP entry for %s available in cache, not sending ARP request.Replying to tour with HW Address:%s\n",
                            findhostname(recvline), t_hwaddr);
                    send(connfd_tour, (void *)&replyToTour, sizeof(replyToTour), 0);
			}
			
		}
		else
		//Message from some other ARP
		if(FD_ISSET(pfsock_arp, &rset))
		{
            #ifdef DEBUG
			printf("Message received from other arp\n");
            #endif

            slen = sizeof(saddr);
            if( (n = recvfrom(pfsock_arp, buffer, ETH_FRAME_LEN, 0, (SA *)&saddr, &slen)) < 0)
            {
                printf("Error receiving packet, errno: %s !Exitting the program\n",strerror(errno));
                exit(-1);
            }
            else
            {
                #ifdef DEBUG
                printf("Received packet from interface %d\n",saddr.sll_ifindex);
                #endif

                void *data = buffer + 14;
                pkt_recd = (struct s_arppkt *) data;

                if(pkt_recd->id != ARPPKT_ID)
                {
                    #ifdef DEBUG
                    printf("Received packet with unknown id %d, ignoring!\n",pkt_recd->id);
                    #endif
                    continue;
                }

                switch(pkt_recd->op)
                {
                    case TYPE_REQ:
                        #ifdef DEBUG
                        printf("Received request\n");
                        #endif
                        if(strcmp(pkt_recd->dst_ip, ifhead->ipaddr) == 0)
                        {
							sprintf(t_hwaddr, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", 
                                pkt_recd->src_mac[0], pkt_recd->src_mac[1], pkt_recd->src_mac[2], 
                                pkt_recd->src_mac[3], pkt_recd->src_mac[4], pkt_recd->src_mac[5]);
							insertToARPCache(pkt_recd->src_ip, t_hwaddr, saddr.sll_ifindex, MAC_HATYPE, pfsock_arp);
							#ifdef DEBUG
							printARPCache();
							#endif
                            strcpy(rephost, findhostname(pkt_recd->dst_ip));
                            strcpy(reqhost, findhostname(pkt_recd->src_ip));
                            printf("ARP REQUEST RECEIVED:\n");
                            printf("Src: %s  Dst: ff:ff:ff:ff:ff:ff arp 60:\n",
                                t_hwaddr);
                            printf("arp who-has %s tell %s\n", reqhost, rephost);
							sendARPReply(pfsock_arp, pkt_recd->src_mac, saddr.sll_ifindex, pkt_recd->src_ip);
                        }
                        break;

                    case TYPE_REP:
						#ifdef DEBUG
							printf("ARP Reply received from %s to %s\n", pkt_recd->src_mac, pkt_recd->dst_mac); 
						#endif
						sprintf(t_hwaddr, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
                            pkt_recd->src_mac[0], pkt_recd->src_mac[1], pkt_recd->src_mac[2],
                            pkt_recd->src_mac[3], pkt_recd->src_mac[4], pkt_recd->src_mac[5]);
						updateCache(pkt_recd->src_ip, t_hwaddr, saddr.sll_ifindex, MAC_HATYPE, pfsock_arp);
						#ifdef DEBUG
						printARPCache();
						#endif

                        strcpy(rephost,findhostname(pkt_recd->src_ip));
                        printf("ARP REPLY RECEIVED:\n");
                        printf("Src: %s Dst: %s arp 60:\n", pkt_recd->src_mac, pkt_recd->dst_mac);
                        printf("arp reply %s is-at %s\n", rephost, t_hwaddr);

                        replyToTour.sll_ifindex = saddr.sll_ifindex;
                        replyToTour.sll_hatype = MAC_HATYPE;
                        replyToTour.sll_halen = sizeof(replyToTour.sll_hatype);
                        for(i=0; i<6; i++)
                            replyToTour.sll_addr[i] = pkt_recd->src_mac[i];
                        replyToTour.sll_addr[6] = 0;
                        replyToTour.sll_addr[7] = 0;
						send(connfd_tour, (void *)&replyToTour, sizeof(replyToTour), 0);
						flagBroadcasted = 0;
						strcpy(partialIP,"");
						close(connfd_tour);
                        break;
                    default:
						printf("Weird ARP Packet received, type : %d, discarding!\n", pkt_recd->op);
                        break;
                }
            }

		}
	}
   
    printf("ARP quitting\n");
    return 1;
}

void broadcastARPRequest(char * IPAddr, int pfsock_arp)
{
	#ifdef DEBUG
	printf("Preparing broadcast message!\n");
	#endif
	int i;
	int send_result = 0;
	unsigned char src_mac[6]; // = {0x00, 0x01, 0x02, 0xFA, 0x70, 0xAA};
    unsigned char dest_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	struct sockaddr_ll saddress;
	void* buffer = (void*)malloc(ETH_FRAME_LEN);
    unsigned char* etherhead = buffer;
    unsigned char* data = buffer + 14;
	struct ethhdr *eh = (struct ethhdr *)etherhead;
    struct s_arppkt pkt_to_send;
    char reqhost[100], rephost[100];
	
	sscanf(ifhead->hwaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
                &src_mac[0],&src_mac[1],&src_mac[2],&src_mac[3],&src_mac[4],&src_mac[5]);
	
	/*prepare sockaddr_ll*/
    saddress.sll_family   = PF_PACKET;    
    saddress.sll_protocol = htons(ETH_P_IP);  
    saddress.sll_hatype   = ARPHRD_ETHER;
    saddress.sll_pkttype  = PACKET_OTHERHOST;
    saddress.sll_halen    = ETH_ALEN;  
	saddress.sll_ifindex = ifhead->ifindex;
	for(i=0;i<6;i++)
		saddress.sll_addr[i] = src_mac[i];
	saddress.sll_addr[6] = 0x00;
	saddress.sll_addr[7] = 0x00;
	
	memcpy((void*)buffer, (void*)dest_mac, ETH_ALEN);
	memcpy((void*)(buffer+ETH_ALEN), (void*)src_mac, ETH_ALEN);
	eh->h_proto = htons(USID_PROTO);

    // Filling the data part
    pkt_to_send.id        = ARPPKT_ID;
    pkt_to_send.hard_type = 1;
    pkt_to_send.prot_type = 0x800;
    pkt_to_send.hard_size = sizeof(pkt_to_send.hard_type);
    pkt_to_send.prot_size = sizeof(pkt_to_send.prot_type);
    pkt_to_send.op        = TYPE_REQ;
    for(i=0;i<6;i++)
		pkt_to_send.src_mac[i] = src_mac[i];
    for(i=0;i<6;i++)
		pkt_to_send.dst_mac[i] = 0;
    strcpy(pkt_to_send.src_ip, ifhead->ipaddr);
    strcpy(pkt_to_send.dst_ip, IPAddr);

	memcpy((void *)data, (void *)&pkt_to_send, sizeof(struct s_arppkt));
	
	#ifdef DEBUG
	printf("Sending broadcast message %s!\n",IPAddr);
	#endif
	#ifdef DEBUG
		printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
		pkt_to_send.src_mac[0],pkt_to_send.src_mac[1],pkt_to_send.src_mac[2],
        pkt_to_send.src_mac[3],pkt_to_send.src_mac[4],pkt_to_send.src_mac[5]);
	#endif
	
	//Adding partial entry to ARP Cache
	insertToARPCache(IPAddr, "", -1, MAC_HATYPE, pfsock_arp);
	#ifdef DEBUG
	printARPCache();
	#endif
	
    strcpy(reqhost, findhostname(pkt_to_send.src_ip));
    strcpy(rephost, findhostname(pkt_to_send.dst_ip));
    printf("BROADCASTING ARP REQUEST:\n");
    printf("Src: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x Dst: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x arp 60:\n",
        src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5],
        dest_mac[0],dest_mac[1],dest_mac[2],dest_mac[3],dest_mac[4],dest_mac[5]);
    printf("arp who-has %s tell %s\n", rephost, reqhost);

	//Actual sending of broadcast message
	send_result = sendto(pfsock_arp, buffer, ETH_FRAME_LEN, 0, 
                (struct sockaddr*)&saddress, sizeof(saddress));
	if (send_result == -1)
		printf("Send error, errno:%s!\n",strerror(errno));
	return;
}

void sendARPReply(int pfsock_arp, unsigned char *sendtomac, int ifindex, char *sendtoIP)
{
	#ifdef DEBUG
	printf("Preparing ARP reply message!\n");
	#endif
	int i, send_result = 0;
	unsigned char src_mac[6]; // = {0x00, 0x01, 0x02, 0xFA, 0x70, 0xAA};
    unsigned char dest_mac[6]; // = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	struct sockaddr_ll saddress;
	void* buffer = (void*)malloc(ETH_FRAME_LEN);
    unsigned char* etherhead = buffer;
    unsigned char* data = buffer + 14;
	struct ethhdr *eh = (struct ethhdr *)etherhead;
    struct s_arppkt pkt_to_send;
    char rephost[100];
	
	sscanf(ifhead->hwaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
                &src_mac[0],&src_mac[1],&src_mac[2],&src_mac[3],&src_mac[4],&src_mac[5]);
	for(i=0; i<6; i++)
		dest_mac[i] = sendtomac[i];
	
	/*prepare sockaddr_ll*/
    saddress.sll_family   = PF_PACKET;    
    saddress.sll_protocol = htons(ETH_P_IP);  
    saddress.sll_hatype   = ARPHRD_ETHER;
    saddress.sll_pkttype  = PACKET_OTHERHOST;
    saddress.sll_halen    = ETH_ALEN;  
	saddress.sll_ifindex  = ifindex;
	for(i=0;i<6;i++)
		saddress.sll_addr[i] = src_mac[i];
	saddress.sll_addr[6] = 0x00;
	saddress.sll_addr[7] = 0x00;
	
	memcpy((void*)buffer, (void*)dest_mac, ETH_ALEN);
	memcpy((void*)(buffer+ETH_ALEN), (void*)src_mac, ETH_ALEN);
	eh->h_proto = htons(USID_PROTO);

    // Filling the data part
    pkt_to_send.id        = ARPPKT_ID;
    pkt_to_send.hard_type = 1;
    pkt_to_send.prot_type = 0x800;
    pkt_to_send.hard_size = sizeof(pkt_to_send.hard_type);
    pkt_to_send.prot_size = sizeof(pkt_to_send.prot_type);
    pkt_to_send.op        = TYPE_REP;
    for(i=0; i<6; i++)
		pkt_to_send.src_mac[i] = src_mac[i];
    for(i=0; i<6; i++)
		pkt_to_send.dst_mac[i] = sendtomac[i];
    strcpy(pkt_to_send.src_ip, ifhead->ipaddr);
    strcpy(pkt_to_send.dst_ip, sendtoIP);

	memcpy((void *)data, (void *)&pkt_to_send, sizeof(struct s_arppkt));
	
	#ifdef DEBUG
	printf("Sending ARP reply%s!\n",ifhead->hwaddr);
	printf("Details of msg sent : Source - %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
	printf("Destination - %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",sendtomac[0], sendtomac[1], sendtomac[2], sendtomac[3], sendtomac[4], sendtomac[5]);
	#endif

    strcpy(rephost, findhostname(pkt_to_send.src_ip));
    printf("SENDING ARP REPLY:\n");
    printf("Src: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x Dst: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x arp 60:\n",
        src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5],
        sendtomac[0],sendtomac[1],sendtomac[2],sendtomac[3],sendtomac[4],sendtomac[5]);
    printf("arp reply %s is-at  %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", rephost, 
            src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
	
	send_result = sendto(pfsock_arp, buffer, ETH_FRAME_LEN, 0, 
                (struct sockaddr*)&saddress, sizeof(saddress));
	if (send_result == -1)
		printf("Send error, errno:%s!\n",strerror(errno));
	return;
}

void createIfList()
{
	struct hwa_info	*hwa, *hwahead;
	struct sockaddr	*sa;
	char   *ptr, ipaddr[16],hwaddr[18],tmp[4];
	int    i, prflag, ifindex;

	for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next) 
    {
        if(strcmp(hwa->if_name,"eth0") != 0)
            continue;
		
		if ( (sa = hwa->ip_addr) != NULL)
            strcpy(ipaddr,(char *)Sock_ntop_host(sa, sizeof(*sa)));
				
		prflag = 0;
		i = 0;
		do {
			if (hwa->if_haddr[i] != '\0') {
				prflag = 1;
				break;
			}
		} while (++i < IF_HADDR);

        strcpy(hwaddr,"");
		if (prflag) {
			ptr = hwa->if_haddr;
			i = IF_HADDR;
			do {
                int j;
				sprintf(tmp,"%.2x%s", *ptr++ & 0xff, (i == 1) ? "" : ":");
                if(i == 1)
                    strncat(hwaddr,tmp,2);
                else
                    strncat(hwaddr,tmp,3);
			} while (--i > 0);
		}

        hwaddr[18] = 0;
		ifindex = hwa->if_index;
		addToIfList(ipaddr, ifindex, hwaddr);
	}

	free_hwa_info(hwahead);
    return;
}

void addToIfList(char *ipaddr, int ifindex, char *hwaddr)
{
    struct s_iflist *temp;
    struct s_iflist *newnode =
        (struct s_iflist*)malloc(sizeof(struct s_iflist));

    strcpy(newnode->ipaddr,ipaddr);
    strcpy(newnode->hwaddr,hwaddr);
	newnode->ifindex = ifindex;
	
    if(ifhead!=NULL)
    {
        temp=ifhead;
        while(temp->next != NULL)
            temp=temp->next;
        temp->next=newnode;
    }
    else
    {
        ifhead = newnode;
    }
    newnode->next=NULL;
}

void printIfaces()
{
    struct s_iflist *temp=ifhead;
    if(temp==NULL)
        return;
    printf("IP Addr\t\tHW Addr\n");
    while(temp != NULL)
    {
        printf("%s\t%s\n",
                 temp->ipaddr, temp->hwaddr);
        temp=temp->next;
    }
    printf("\n");
}

void insertToARPCache(char * ipaddr, char *hwaddr, int ifindex, int sll_hatype, int connfd_arp)
{
	#ifdef DEBUG
		printf("Insert to ARP Cache\n");
	#endif
	struct s_ARP_cache *temp;
	struct s_ARP_cache *newnode = (struct s_ARP_cache*)malloc(sizeof(struct s_ARP_cache));
	
	if( strcmp(ipaddr,"") != 0 )
		strcpy(newnode ->ipaddr, ipaddr);
	else
	{
		printf("Attempt to add invalid IP to cache\n");
		return;
	}
	strcpy(newnode ->hwaddr, hwaddr);
	newnode ->ifindex = ifindex; 
	newnode ->sll_hatype = sll_hatype;
	newnode ->connfd_arp = connfd_arp;
	if(ARP_cache_head!=NULL)
    {
        temp=ARP_cache_head;
        while(temp->next != NULL)
            temp=temp->next;
        temp->next=newnode;
    }
    else
    {
        ARP_cache_head = newnode;
    }
	newnode->next=NULL;
	#ifdef DEBUG
		printf("Insert completed to ARP Cache, added %s\n", ipaddr);
	#endif
}

void lookupCache(char * IPAddr, char * hwaddr, int * ifindex, int * hatype)
{
	#ifdef DEBUG
		printf("Looking at ARP Cache for %s\n", IPAddr);
	#endif
	struct s_ARP_cache *temp;
	temp = ARP_cache_head;
	
	strcpy(hwaddr, "");
	*ifindex = -1;
	
	if( temp == NULL )
		return;
	else
	{
		while(temp != NULL)
		{
			if( strcmp(IPAddr, temp->ipaddr) == 0 && temp->hwaddr!=NULL)
			{
				strcpy(hwaddr, temp->hwaddr);
				*ifindex = temp->ifindex;
				*hatype = temp->sll_hatype;
				return;
			}
			else
				temp = temp->next;
		}
		return;
	}
}

void updateCache(char * ipaddr, char *hwaddr, int ifindex, int sll_hatype, int connfd_arp)
{
	struct s_ARP_cache *temp;
	temp = ARP_cache_head;
	
	while(temp != NULL)
	{
		if( strcmp(ipaddr, temp->ipaddr) == 0)
		{
			if( hwaddr != NULL)
				strcpy(temp ->hwaddr, hwaddr);
			else
			{
				printf("Invalid update operation on ARP Cache\n");
				return;
			}
			temp ->ifindex = ifindex; 
			temp ->sll_hatype = sll_hatype;
			temp ->connfd_arp = connfd_arp;
			#ifdef DEBUG
				printf("Update completed to ARP Cache, added %s | %s\n", ipaddr, hwaddr);
			#endif
			return;
		}
		temp = temp->next;
	}
	printf("Invalid update operation on ARP Cache\n");
	return;
	
}

void printARPCache()
{
	#ifdef DEBUG
		printf("ARP Cache -\n");
	#endif
	struct s_ARP_cache *temp;
	temp = ARP_cache_head;
	
	while( temp != NULL )
	{
		printf("%s | %s\n", temp->ipaddr, temp->hwaddr);
		temp = temp-> next;
	}
}

void deleteFromARPCache(char *ipaddr)
{
    struct s_ARP_cache *temp,*todelete;
    temp = ARP_cache_head;
    if(temp == NULL || strcmp(ipaddr,"") == 0)
        return;
    if(strcmp(ARP_cache_head->ipaddr, ipaddr) == 0 &&
        strcmp(ARP_cache_head->hwaddr, "") == 0)
    {
        ARP_cache_head=temp->next;
        todelete = temp;
    }
    else
    {
        while(temp->next !=NULL)
        {
            if( (strcmp(temp->next->ipaddr, ipaddr) == 0) &&
                (strcmp(temp->next->hwaddr, "") == 0))
            {
                todelete = temp->next;
                temp->next = todelete->next;
                break;
            }
            temp = temp->next;
        }
    }
    todelete = NULL;
    free(todelete);
}

char *findhostname(char *ipaddr)
{
    struct hostent *he;
    struct in_addr addrinfo;
    inet_pton(AF_INET, ipaddr, &addrinfo);
    he = gethostbyaddr(&addrinfo, sizeof(addrinfo), AF_INET);

    return(he->h_name);
}
