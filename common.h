#define NODEBUG
#include <stdint.h>

#define ARP_PATH "/tmp/arp.7156"
#define USID_PROTO 7156
#define TOUR_PROT 65
#define ARPPKT_ID 0x7156
#define TOUR_ID 9365
#define ETH_FRAME_LEN 1514
#define TYPE_REQ 1
#define TYPE_REP 2
#define NOTFOUND 0
#define FOUND 1
#define MAC_HATYPE 1
#define TOURMSG_SIZE (sizeof(struct iphdr) + sizeof(struct s_tour_pkt))
#define MCAST_ADDR "239.0.0.1"
#define MCAST_PORT "6000"
#define	BUFSIZE	1500
#define ETH_HDRLEN 14
#define IP4_HDRLEN 20  // IPv4 header length
#define ICMP_HDRLEN 8  // ICMP header length for echo request, excludes data
#define ETH_FRAME_LEN 1514

char ping_sendbuf[BUFSIZE];
int	datalen = 56;		/* data that goes with ICMP echo request */

struct hwaddr {
    int             sll_ifindex;    /* Interface number */
    unsigned short  sll_hatype;     /* Hardware type */
    unsigned char   sll_halen;      /* Length of address */
    unsigned char   sll_addr[8];    /* Physical layer address */
};

struct s_iflist
{
    char ipaddr[16];
    char hwaddr[18];
	int ifindex;
    struct s_iflist *next;
};
struct s_iflist *ifhead;

struct s_arppkt
{
    uint16_t id;
    uint16_t hard_type;
    uint16_t prot_type;
    uint8_t  hard_size;
    uint8_t  prot_size;
    uint16_t op;
    unsigned char src_mac[6];
    char src_ip[16];
    unsigned char dst_mac[6];
    char dst_ip[16];
};

struct s_ARP_cache
{
	char ipaddr[16];
    char hwaddr[18];
	int ifindex;
	int sll_hatype;
	int connfd_arp;
	struct s_ARP_cache *next;
};
struct s_ARP_cache *ARP_cache_head;

struct s_tour_pkt
{
	char multicastAddress[16];
	char multicastPort[5];
	char tourIPs[16][16];
	int currPosition; //Points to element just visited
};

struct s_multicast_msg
{
	char message[200];
	int endofTourFlag;
};

uint16_t in_cksum(uint16_t *addr, int len)
{
        int nleft = len;
        uint32_t sum = 0;
        uint16_t *w = addr;
        uint16_t answer = 0;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

                /* 4mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(unsigned char *)(&answer) = *(unsigned char *)w ;
                sum += answer;
        }

                /* 4add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}
