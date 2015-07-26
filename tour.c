#include    "common.h"
#include    "hw_addrs.h"
#include    "unp.h"
#include    <sys/utsname.h>
#include    <netinet/in_systm.h>
#include    <netinet/ip.h>
#include    <netinet/ip_icmp.h>
#include    <linux/if_ether.h>
#include    <linux/if_packet.h>
#include    <time.h>


void stub_main(char *);
int areq(struct sockaddr *, socklen_t, struct hwaddr *);
void printTour(void);
void sendTour(int);
void ping_send(int , char *);
void ping_receive(int);
void ping_receive_process(char *, ssize_t, struct msghdr *, struct timeval *, struct sockaddr *);
void createIfList(void);
void addToIfList(char *, int, char *);
uint16_t checksum (uint16_t *, int);
uint16_t icmp4_checksum (struct icmp , uint8_t *, int );
char *findhostname(char *);

struct s_tour_pkt * tour_pkt;
int nsent = 0;


int main(int argc, char **argv)
{
    struct hostent *host;
    char ipaddr[16];
	char to_ping_IP[16];
	char endOfTour[12];
	char recvline[12];
	int i = 0, n, slen, sockraw_tour, sock_ping_send, sock_ping_receive, sendfd_mcast, recvfd_mcast;
	int size, maxfd, len;
	const int on = 1;
	struct utsname myname;
    struct sockaddr_in saddr;
    struct sockaddr *sasend, *sarecv;
    socklen_t salen;
    void *buffer = (void *)malloc (TOURMSG_SIZE);
	struct s_tour_pkt tour_pkt_recv;
	struct s_multicast_msg multicast_msg, multicast_msg_recv;
	struct timeval tv_endTour, tv_toPing;
    fd_set rset;
	tour_pkt = (struct s_tour_pkt *)malloc(sizeof(struct s_tour_pkt));
	uname(&myname);
	FD_ZERO(&rset);
	int joinedTourFlag = 0;
	int pingSentFlag = 0;
	int endOfTourFlag = 0;
	int tourEnded = 0;
	struct sockaddr  *ping_sarecv;	/* sockaddr{} for receiving */
	socklen_t ping_salen;
    time_t now;
	
	multicast_msg.endofTourFlag = -1;
	strcpy(multicast_msg.message, "");
	multicast_msg_recv.endofTourFlag = -1;
	strcpy(multicast_msg_recv.message, "");
    ifhead = NULL;
    createIfList();

    printf("Tour process started.\n");
	
	for(i=0; i<16; i++)
		strcpy(tour_pkt->tourIPs[i], "");
	strcpy(endOfTour, "");
	
    //Creating all the sockets
	sockraw_tour = Socket(AF_INET, SOCK_RAW, TOUR_PROT);
	if( setsockopt(sockraw_tour, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		printf("Socket option error, quitting tour\n");
		exit(0);		
	}
	
	//Socket configuration for ping
	/*sock_ping_send = Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	size = 60 * 1024;	
	setsockopt(sock_ping_send, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));*/

    sock_ping_send = Socket(PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
	
	sock_ping_receive = Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	size = 60 * 1024;		/* OK if setsockopt fails */
	setsockopt(sock_ping_receive, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

	if(argc > 1)
	{
		//Building tour packet
		if( (host = gethostbyname(myname.nodename)) == NULL )
		{
			printf("Invalid input! Tour terminated\n");
			exit(0);
		}
		inet_ntop(AF_INET,*(host->h_addr_list),ipaddr,sizeof(ipaddr));
		strcpy(tour_pkt->tourIPs[0], ipaddr);

		for(i=1; i<argc; i++)
		{
			if(strncmp(argv[i],"vm",2) != 0)
			{
				printf("Invalid input! Tour terminated\n");
				exit(0);
			}
			if( (host = gethostbyname(argv[i])) == NULL )
			{
				printf("Invalid input! Tour terminated\n");
				exit(0);
			}
			inet_ntop(AF_INET,*(host->h_addr_list),ipaddr,sizeof(ipaddr));
			strcpy(tour_pkt->tourIPs[i], ipaddr);
		}
		
		tour_pkt->currPosition = 0;
		strcpy(tour_pkt->multicastAddress, MCAST_ADDR);
		strcpy(tour_pkt->multicastPort, MCAST_PORT);
		
        printTour();
		//Sending tour packet
		sendTour(sockraw_tour);
		
		sendfd_mcast = Udp_client(MCAST_ADDR, MCAST_PORT, (SA **)&sasend, &salen);
		recvfd_mcast = Socket(sasend->sa_family, SOCK_DGRAM, 0);
		Setsockopt(recvfd_mcast, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		Mcast_join(recvfd_mcast, sasend, salen, NULL, 0);
		Mcast_set_loop(sendfd_mcast, 1);

		sarecv = Malloc(salen);
		memcpy(sarecv, sasend, salen);
		Bind(recvfd_mcast, sarecv, salen);
		joinedTourFlag = 1;
	}

    for(;;)
    {
        FD_SET(sockraw_tour, &rset);
		if(joinedTourFlag == 1 && pingSentFlag == 1)
		{
			FD_SET(recvfd_mcast, &rset);
			FD_SET(sock_ping_receive, &rset);
			maxfd = max(recvfd_mcast, max(sock_ping_receive, sockraw_tour)) +1;
			tv_toPing.tv_sec = 1;
			tv_toPing.tv_usec = 0;
		}
		else if(joinedTourFlag == 1)
		{
			FD_SET(recvfd_mcast, &rset);
			maxfd = max(recvfd_mcast, sockraw_tour) +1;
		}
		else
			maxfd = sockraw_tour +1;

        if(select(maxfd, &rset, NULL, NULL, &tv_toPing) < 0)
        {
            if(errno == EINTR)
                continue;
            else
            {
                printf("Select error! Quitting tour\n");
                exit(0);
            }
        }
		if(FD_ISSET(sockraw_tour, &rset))
        {
            slen = sizeof(saddr);
            if( (n = recvfrom(sockraw_tour, buffer, TOURMSG_SIZE, 0, (SA*)&saddr, &slen)) < 0)
            {
                printf("Error receiving packet,errno: %s! Quitting program\n",strerror(errno));
                exit(0);
            }
            else
			{
                tour_pkt = (struct s_tour_pkt *)(buffer + sizeof(struct iphdr));
				#ifdef DEBUG
				printf("Joining the tour, message from %s\n", tour_pkt->tourIPs[(tour_pkt->currPosition)-1]);
				#endif
                now = time(NULL);
                printf("%s: Received source routing pkt from %s\n", ctime(&now),
                        findhostname(tour_pkt->tourIPs[(tour_pkt->currPosition)-1]) );
				if( joinedTourFlag != 1)
				{
					#ifdef DEBUG
					printf("Joining multicast group - %s | %s\n", tour_pkt->multicastAddress, tour_pkt->multicastPort);
					#endif
					sendfd_mcast = Udp_client(tour_pkt->multicastAddress, tour_pkt->multicastPort, (SA **)&sasend, &salen);
					recvfd_mcast = Socket(sasend->sa_family, SOCK_DGRAM, 0);
					Setsockopt(recvfd_mcast, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
					Mcast_join(recvfd_mcast, sasend, salen, NULL, 0);
					Mcast_set_loop(sendfd_mcast, 1);

					sarecv = Malloc(salen);
					memcpy(sarecv, sasend, salen);
					Bind(recvfd_mcast, sarecv, salen);
					strcpy(to_ping_IP, tour_pkt->tourIPs[(tour_pkt->currPosition)-1]);
					ping_send(sock_ping_send, to_ping_IP);
					joinedTourFlag = 1;
					pingSentFlag = 1;
				}
				if(strcmp(tour_pkt->tourIPs[tour_pkt->currPosition+1], "") != 0)
                {
                    //Intermediate nodes of the tour
					sendTour(sockraw_tour);
                }
                else
                {
                    #ifdef DEBUG
                    printf("I am the last node, no more sending\n");
                    #endif
					//Send multicast message
					strcpy(endOfTour, "End of Tour");
					sprintf(multicast_msg.message, "This is node %s. Tour has ended. Group members please identify yourselves.", myname.nodename);
					multicast_msg.endofTourFlag = 1;
					ping_receive(sock_ping_receive);
					for(i=0; i<4; i++)
					{
						ping_send(sock_ping_send, to_ping_IP);
						ping_receive(sock_ping_receive);
					}
					printf("Sending : \"%s\"\n", multicast_msg.message);
					Sendto(sendfd_mcast, (char *)&multicast_msg, sizeof(struct s_multicast_msg), 0, sasend, salen);
					endOfTourFlag = 1;
                }
				
			}	
        }
		else if(FD_ISSET(recvfd_mcast, &rset))
		{
			len = salen;
			if( (n = Recvfrom(recvfd_mcast, (char *)&multicast_msg_recv, sizeof(struct s_multicast_msg), 0, sarecv, &len)) <= 0)
			{
				printf("Receive from multicast failed, errno: %s!\n",strerror(errno));
				return(-1);
			}
			else
			{
				if( multicast_msg_recv.endofTourFlag == 1)
				{
					printf("Received : \"%s\"\n", multicast_msg_recv.message);
					sprintf(multicast_msg.message, "Node %s. I am a member of this group.", myname.nodename);
					multicast_msg.endofTourFlag = 0;
					printf("Sending : \"%s\"\n", multicast_msg.message);
					Sendto(sendfd_mcast, (char *)&multicast_msg, sizeof(struct s_multicast_msg), 0, sasend, salen);
					
					//Select to receive other closing messages
					FD_ZERO(&rset);
					FD_SET(recvfd_mcast, &rset);
					maxfd = recvfd_mcast +1;
					tv_endTour.tv_sec = 5;
					tv_endTour.tv_usec = 0;
					for(;;)
					{
						if(select(maxfd, &rset, NULL, NULL, &tv_endTour) < 0)
						{
							if(errno == EINTR)
								continue;
							else
							{
								printf("Select error! Quitting tour\n");
								exit(0);
							}
						}

						if(FD_ISSET(recvfd_mcast, &rset))
						{
							if( (n = Recvfrom(recvfd_mcast, (char *)&multicast_msg_recv, sizeof(struct s_multicast_msg), 0, sarecv, &len)) <= 0)
							{
								printf("Receive from multicast failed, errno: %s!\n", strerror(errno));
								return(-1);
							}
							else
							{
								printf("Received : \"%s\"\n", multicast_msg_recv.message);
								continue;
							}
						}
						else
						{
							printf("Closing tour\n");
							exit(1);
						}
					}
				}
			}
		}
		else if( (endOfTourFlag ==0) && (joinedTourFlag == 1) && (FD_ISSET(sock_ping_receive, &rset)) )
				ping_receive(sock_ping_receive);
		else
		{
			#ifdef DEBUG
				printf("Select timeout, pinging previous node\n");
			#endif
			ping_send(sock_ping_send, to_ping_IP);
		}
    }
	
    //stub_main(ipaddr);
    return 0;
}

int areq(struct sockaddr *IPaddr, socklen_t sockaddrlen, struct hwaddr *reqd)
{
    int    n, sockfd;
    struct sockaddr_un  servaddr;
    char pIP[16], recvline[MAXLINE];
    fd_set rset;
    struct timeval rem_time;

    FD_ZERO(&rset);

    strcpy(pIP, (char *)Sock_ntop_host(IPaddr, sizeof(struct sockaddr)) );
    printf("areq() API has been called: seeking HW address for IP %s\n",pIP);

    #ifdef DEBUG
    printf("Sending arp req for %s\n",pIP);
    #endif

    sockfd = Socket(AF_LOCAL, SOCK_STREAM, 0);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_LOCAL;
    strcpy(servaddr.sun_path, ARP_PATH);
    Connect(sockfd, (SA *) &servaddr, sizeof(servaddr));
    
    send(sockfd, pIP, sizeof(pIP), 0);

    FD_SET(sockfd, &rset);
    rem_time.tv_sec = 5;
    rem_time.tv_usec = 0;
    Select(sockfd+1, &rset, NULL, NULL, &rem_time);

    if(FD_ISSET(sockfd, &rset))
    {
        if( (n = recv(sockfd, (void *)reqd, sizeof(struct hwaddr), 0)) <= 0)
        {
            printf("Receive from ARP socket failed, areq() returning with failure!\n");
            return(-1);
        }
    }
    else
    {
        //Timeout occured and no reply from ARP
        printf("Timed out on response from ARP! Closing socket and giving up. areq() returning with failure\n");
        close(sockfd);
        return(-1);
    }
    printf("areq() returning: HW address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
            reqd->sll_addr[0],reqd->sll_addr[1],reqd->sll_addr[2],reqd->sll_addr[3],reqd->sll_addr[4],reqd->sll_addr[5]);
    return(1);
}

void printTour()
{
	int i = 0;
	#ifdef DEBUG
		
	printf("Tour -\n");
	printf("Multicast Details - %s | %s\n", tour_pkt->multicastAddress, tour_pkt->multicastPort);
	printf("Tour IPs are -\n");
	for(i = 0; strcmp(tour_pkt->tourIPs[i], "") !=0; i++)
		printf("%s\t", tour_pkt->tourIPs[i]);
	printf("\n");
	#endif
    return;
}

void sendTour(int sockraw_tour)
{
	struct iphdr *ip_hdr;
	struct sockaddr_in src, dst;
	void* buffer = (void *)malloc( sizeof(struct s_tour_pkt) + sizeof(struct iphdr) );
	unsigned char * data = buffer + sizeof(struct iphdr);
	ip_hdr = (struct iphdr *)buffer;
	
	//Creating header 
	ip_hdr->ihl = 5; 
	ip_hdr->version = 4;
	ip_hdr->tos = 0;
	ip_hdr->tot_len = sizeof(struct iphdr) + sizeof(struct s_tour_pkt);
	ip_hdr->id = TOUR_ID;
	ip_hdr->ttl = 64;
	ip_hdr->protocol = TOUR_PROT;
	
	src.sin_addr.s_addr = inet_addr(tour_pkt->tourIPs[tour_pkt->currPosition]);
	dst.sin_addr.s_addr = inet_addr(tour_pkt->tourIPs[tour_pkt->currPosition + 1]);
	dst.sin_family = AF_INET;
	tour_pkt->currPosition++;
	ip_hdr->saddr = src.sin_addr.s_addr;
	ip_hdr->daddr = dst.sin_addr.s_addr;
	ip_hdr->check = in_cksum((unsigned short *)ip_hdr, sizeof(struct iphdr));
	
	//Creating data
	memcpy(data, (void *)tour_pkt, sizeof(struct s_tour_pkt));
	if(sendto(sockraw_tour, buffer, (sizeof(struct s_tour_pkt) + sizeof(struct iphdr)), 0, (SA *)&dst, sizeof(struct sockaddr_in)) <= 0)
    {
        printf("Send failed, errno: %s! Quitting tour\n",strerror(errno));
        exit(0);
    }
    #ifdef DEBUG
        printf("Packet sent to %s\n",tour_pkt->tourIPs[tour_pkt->currPosition]);
    #endif
	
}

void ping_send(int sock_ping_send, char * IPAddr)
{
	int i, len, size, data_len, ip_flags[4];
    int sockfd, status, frame_length, ether_frame[ETH_FRAME_LEN];
	struct sockaddr_in ping_sasend, sa={};	/* sockaddr{} for send, from getaddrinfo */
    struct sockaddr_ll device;
    struct hwaddr reqd;
    struct ip iphdr;
    struct icmp icmphdr, *icmp;
	pid_t pid;
    unsigned char src_mac[6], dest_mac[6];
    char src_ip[16], dst_ip[16],data[4], toprint[16];

	pid = getpid() & 0xffff;

    sscanf(ifhead->hwaddr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &src_mac[0],&src_mac[1],&src_mac[2],&src_mac[3],&src_mac[4],&src_mac[5]);

    sa.sin_family = AF_INET;
    Inet_pton(AF_INET, IPAddr, &(sa.sin_addr));

    if( (areq((SA *)&sa, sizeof(sa), &reqd)) == -1)
    {
         printf("ARP Request failed, cannot ping\n");
         return;
    }

    for(i=0;i<6;i++)
        dest_mac[i] = reqd.sll_addr[i];

    strcpy(src_ip, ifhead->ipaddr);
    strcpy(dst_ip, IPAddr);
    device.sll_ifindex = ifhead->ifindex;
    device.sll_family = AF_PACKET;
    memcpy (device.sll_addr, src_mac, 6);
    device.sll_halen = ETH_ALEN;

    // ICMP data
    data_len = 4;
    data[0] = 'T';
    data[1] = 'e';
    data[2] = 's';
    data[3] = 't';

    // IPv4 header
    // IPv4 header length (4 bits): Number of 32-bit words in header = 5
    iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);
    // Internet Protocol version (4 bits): IPv4
    iphdr.ip_v = 4;
    // Type of service (8 bits)
    iphdr.ip_tos = 0;
    // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
    iphdr.ip_len = (IP4_HDRLEN + ICMP_HDRLEN + data_len);
    // ID sequence number (16 bits): unused, since single datagram
    iphdr.ip_id = (0);
    for(i=0; i<4; i++)
        ip_flags[i] = 0;

    iphdr.ip_off = ((ip_flags[0] << 15)
            + (ip_flags[1] << 14)
            + (ip_flags[2] << 13)
            +  ip_flags[3]);

    iphdr.ip_ttl = 255;
    iphdr.ip_p = IPPROTO_ICMP;
    
    // Source IPv4 address (32 bits)
    if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
        fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }

    // Destination IPv4 address (32 bits)
    if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
        fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }

    // IPv4 header checksum (16 bits): set to 0 when calculating checksum
    //iphdr.ip_sum = 0;
    //iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);

    // ICMP header
    // Message Type (8 bits): echo request
    icmphdr.icmp_type = ICMP_ECHO;
    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;
    // Identifier (16 bits): usually pid of sending process - pick a number
    icmphdr.icmp_id = pid;
    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = nsent++;
    // ICMP header checksum (16 bits): set to 0 when calculating checksum
    icmphdr.icmp_cksum = icmp4_checksum (icmphdr, data, data_len);
    frame_length = 6 + 6 + 2 + IP4_HDRLEN + ICMP_HDRLEN + data_len;
    memcpy (ether_frame, dest_mac, 6);
    memcpy (ether_frame + 6, src_mac, 6);

    ether_frame[12] = ETH_P_IP / 256;
    ether_frame[13] = ETH_P_IP % 256;

    memcpy (ether_frame + ETH_HDRLEN, &iphdr, IP4_HDRLEN);
    memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN, &icmphdr, ICMP_HDRLEN);
    memcpy (ether_frame + ETH_HDRLEN + IP4_HDRLEN + ICMP_HDRLEN, data, data_len);

	//Sendto(sock_ping_send, ether_frame, frame_length, 0, (SA *)&device, sizeof(device));

    sockfd = Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    size = 60 * 1024;       /* OK if setsockopt fails */
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

    bzero(&ping_sasend, sizeof(ping_sasend));
    ping_sasend.sin_family = AF_INET;
    Inet_pton(AF_INET, IPAddr, &(ping_sasend.sin_addr));

    icmp = (struct icmp *) ping_sendbuf;
    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_id = pid;
    icmp->icmp_seq = nsent++;
    memset(icmp->icmp_data, 0xa5, datalen); /* fill with pattern */

    Gettimeofday((struct timeval *) icmp->icmp_data, NULL);

    len = 8 + datalen;      /* checksum ICMP header and data */
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = in_cksum((u_short *) icmp, len);
	#ifdef DEBUG
	printf("Pinging data to be sent to %.2x:%.2x:%.2x:%.2x:%.2x:%.2x , IP: %s\n", 
            dest_mac[0],dest_mac[1],dest_mac[2],dest_mac[3],dest_mac[4],dest_mac[5],
             Sock_ntop_host((SA *)(&ping_sasend), sizeof(struct sockaddr_in)));
	#endif
    strcpy(toprint, Sock_ntop_host((SA *)(&ping_sasend), sizeof(struct sockaddr_in)));
    printf("PING %s (%s) : %d data bytes\n",
            toprint, findhostname(toprint), datalen);

    Sendto(sockfd, ping_sendbuf, len, 0, (SA *)&ping_sasend, sizeof(ping_sasend));
}

void ping_receive(int sockfd)
{
	int size;
	char recvbuf[BUFSIZE];
	char controlbuf[BUFSIZE];
	struct msghdr msg;
	struct iovec iov;
	ssize_t n;
	struct timeval tval;
	struct sockaddr ping_sareceive;

	iov.iov_base = recvbuf;
	iov.iov_len = sizeof(recvbuf);
	msg.msg_name = &ping_sareceive;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = controlbuf;
	msg.msg_namelen = sizeof(struct sockaddr);
	msg.msg_controllen = sizeof(controlbuf);
	n = recvmsg(sockfd, &msg, 0);
	if (n < 0) {
		printf("Recvmsg error, errno: %s\n",strerror(errno));
		exit(0);
	}
	Gettimeofday(&tval, NULL);
	ping_receive_process(recvbuf, n, &msg, &tval, &ping_sareceive);
}

void ping_receive_process(char *ptr, ssize_t len, struct msghdr *msg, struct timeval *tvrecv, struct sockaddr *p_ping_receive)
{
	int hlen1, icmplen;
	double rtt;
	struct ip *ip;
	struct icmp *icmp;
	struct timeval *tvsend;
	pid_t pid;
	pid = getpid() & 0xffff;

	ip = (struct ip *) ptr;		/* start of IP header */
	hlen1 = ip->ip_hl << 2;		/* length of IP header */
	if (ip->ip_p != IPPROTO_ICMP)
    {
        #ifdef DEBUG
        printf("Received NON_ICMP pkt\n");
        #endif
		return;				/* not ICMP */
    }

	icmp = (struct icmp *) (ptr + hlen1);	/* start of ICMP header */
	if ( (icmplen = len - hlen1) < 8)
    {
        #ifdef DEBUG
        printf("Malformed packet\n");
        #endif
		return;				/* malformed packet */
    }

	if (icmp->icmp_type == ICMP_ECHOREPLY) {
		if (icmp->icmp_id != pid)
        {
            #ifdef DEBUG
            printf("not my pid\n");
            #endif
			return;			/* not a response to our ECHO_REQUEST */
        }
		if (icmplen < 16)
        {
            #ifdef DEBUG
            printf("Not enough data in ping reply\n");
            #endif
			return;			/* not enough data to use */
        }

		tvsend = (struct timeval *) icmp->icmp_data;
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

		printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n ",
				icmplen, Sock_ntop_host(p_ping_receive, sizeof(struct sockaddr)),
				icmp->icmp_seq, ip->ip_ttl, rtt);

	}
}

void createIfList()
{
    struct hwa_info *hwa, *hwahead;
    struct sockaddr *sa;
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


// Checksum function
uint16_t checksum (uint16_t *addr, int len)
{
    int nleft = len;
    int sum = 0;
    uint16_t *w = addr;
    uint16_t answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= sizeof (uint16_t);
    }

    if (nleft == 1) {
        *(uint8_t *) (&answer) = *(uint8_t *) w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

// Build IPv4 ICMP pseudo-header and call checksum function.
uint16_t icmp4_checksum (struct icmp icmphdr, uint8_t *payload, int payloadlen)
{
    char buf[IP_MAXPACKET];
    char *ptr;
    int chksumlen = 0;
    int i;

    ptr = &buf[0];  // ptr points to beginning of buffer buf

    // Copy Message Type to buf (8 bits)
    memcpy (ptr, &icmphdr.icmp_type, sizeof (icmphdr.icmp_type));
    ptr += sizeof (icmphdr.icmp_type);
    chksumlen += sizeof (icmphdr.icmp_type);

    // Copy Message Code to buf (8 bits)
    memcpy (ptr, &icmphdr.icmp_code, sizeof (icmphdr.icmp_code));
    ptr += sizeof (icmphdr.icmp_code);
    chksumlen += sizeof (icmphdr.icmp_code);

    // Copy ICMP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 2;

    // Copy Identifier to buf (16 bits)
    memcpy (ptr, &icmphdr.icmp_id, sizeof (icmphdr.icmp_id));
    ptr += sizeof (icmphdr.icmp_id);
    chksumlen += sizeof (icmphdr.icmp_id);

    // Copy Sequence Number to buf (16 bits)
    memcpy (ptr, &icmphdr.icmp_seq, sizeof (icmphdr.icmp_seq));
    ptr += sizeof (icmphdr.icmp_seq);
    chksumlen += sizeof (icmphdr.icmp_seq);

    // Copy payload to buf
    memcpy (ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i=0; i<payloadlen%2; i++, ptr++) {
        *ptr = 0;
        ptr++;
        chksumlen++;
    }

    return checksum ((uint16_t *) buf, chksumlen);
}

char *findhostname(char *ipaddr)
{
    struct hostent *he;
    struct in_addr addrinfo;
    inet_pton(AF_INET, ipaddr, &addrinfo);
    he = gethostbyaddr(&addrinfo, sizeof(addrinfo), AF_INET);

    return(he->h_name);
}

/*
 * Stub function to test areq functionality.
 */
void stub_main(char *cli)
{
    struct sockaddr_in sa={};
    struct hwaddr reqd;
    char ipaddr[16];
    strcpy(ipaddr, cli);

    sa.sin_family = AF_INET;
    // store this IP address in sa:
    Inet_pton(AF_INET, ipaddr, &(sa.sin_addr));

    //printf("caller: family:%d\n",sa->sa_family);

    if( (areq((SA *)&sa, sizeof(sa), &reqd)) == -1)
    {
        printf("ARP Request failed, quitting!\n");
        exit(-1);
    }

    printf("Received from ARP: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
           reqd.sll_addr[0], reqd.sll_addr[1], reqd.sll_addr[2], reqd.sll_addr[3], reqd.sll_addr[4], reqd.sll_addr[5] );
}
