#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, INET_ADDRSTRLEN
#include <netinet/ip.h>       // IP_MAXPACKET (which is 65535)
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <linux/if_ether.h>   // ETH_P_ARP = 0x0806
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h>            // errno, perror()

#define PRINTF_LIST(list, size) {int i = 0; for(i = 0;i < size; i++){printf("%x ", list[i]);} printf("\n");}
#define PRINTF_STRUCT(str, size) {uint8_t *list = (uint8_t*)&str; PRINTF_LIST(list, size)}

#define ETH_HDRLEN 14      // Ethernet header length
#define IP4_HDRLEN 20      // IPv4 header length
#define ARP_HDRLEN 28      // ARP header length
#define ARPOP_REQUEST 1    // Taken from <linux/if_arp.h>

struct arp_hdr {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t opcode;
  uint8_t sender_mac[6];
  uint8_t sender_ip[4];
  uint8_t target_mac[6];
  uint8_t target_ip[4];
};

static int raw_socket_id = -1;
static uint8_t src_mac[6];
static uint8_t src_ip[4];
static uint8_t src_netmask[4];
static uint8_t base_addr[4];
static uint32_t ip_counter = 0;
static uint32_t ip_counter_mask = 0;

static struct sockaddr_ll src_device;
static struct arp_hdr arphdr;
static unsigned int inf_index = 0;
static uint8_t *ether_frame = NULL;
static int arp_recv_interrupted = 0;

int arp_send_init(const char *interface)
{
    struct ifreq ifr;
    if ((inf_index = if_nametoindex(interface)) == 0 ) {
        perror("arp_send_init: failed to get interface index");
        return -1;
    }

    raw_socket_id = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_socket_id < 0) {
        perror("arp_send_init: failed to acquire a socket descriptior.");
        return -1;
    }

    memset(&ifr, 0, sizeof (ifr));
    snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
    if (ioctl (raw_socket_id, SIOCGIFHWADDR, &ifr) < 0) {
        perror("arp_send_init: failed to get source MAC address.");
        return -1;
    }
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof(uint8_t));

    if (ioctl (raw_socket_id, SIOCGIFADDR, &ifr) < 0) {
        perror("arp_send_init: failed to get source ip address.");
        return -1;
    }
    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(src_ip, &ipaddr->sin_addr, 4 * sizeof(uint8_t));

    if (ioctl (raw_socket_id, SIOCGIFNETMASK, &ifr) < 0) {
        perror("arp_send_init: failed to get source netmask address.");
        return -1;
    }
    ipaddr = (struct sockaddr_in*)&ifr.ifr_netmask;
    memcpy(src_netmask, &ipaddr->sin_addr, 4 * sizeof(uint8_t));

    printf("%u.%u.%u.%u\t%u.%u.%u.%u\n", src_ip[0], src_ip[1], src_ip[2], src_ip[3], src_netmask[0], src_netmask[1], src_netmask[2], src_netmask[3]);

    int i = 0;
    for (i = 0; i < 4; i++) {
        base_addr[i] = src_ip[i] & src_netmask[i];
        ip_counter_mask <<= 8;
        ip_counter_mask |= (uint8_t)(~src_netmask[i] & 0xFF);
    }
    printf("%x\n", ip_counter_mask);

    memset (&src_device, 0, sizeof(src_device));
    src_device.sll_ifindex = (int)inf_index;
    src_device.sll_family = AF_PACKET;
    memcpy(src_device.sll_addr, src_mac, 6 * sizeof (uint8_t));
    src_device.sll_halen = 6;

    memcpy(arphdr.sender_ip, src_ip, 4 * sizeof(uint8_t));

    // Hardware type (16 bits): 1 for ethernet
    arphdr.htype = htons (1);

    // Protocol type (16 bits): 2048 for IP
    arphdr.ptype = htons (ETH_P_IP);

    // Hardware address length (8 bits): 6 bytes for MAC address
    arphdr.hlen = 6;

    // Protocol address length (8 bits): 4 bytes for IPv4 address
    arphdr.plen = 4;

    // OpCode: 1 for ARP request
    arphdr.opcode = htons(1);

    // Sender hardware address (48 bits): MAC address
    memcpy (arphdr.sender_mac, src_mac, 6 * sizeof (uint8_t));

    // Target hardware address (48 bits): zero, since we don't know it yet.
    memset (arphdr.target_mac, 0, 6 * sizeof (uint8_t));

    close(raw_socket_id);
    raw_socket_id = -1;

    raw_socket_id = socket(PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
    ether_frame = (uint8_t*)calloc(IP_MAXPACKET, 1);

    // Destination and Source MAC addresses
    memset (ether_frame, 0xff, 6 * sizeof (uint8_t));
    memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));

    // Next is ethernet type code (ETH_P_ARP for ARP).
    // http://www.iana.org/assignments/ethernet-numbers
    ether_frame[12] = ETH_P_ARP / 256;
    ether_frame[13] = ETH_P_ARP % 256;

    return raw_socket_id >= 0 ? 0 : -1;
}

void arp_send_close()
{
    if (raw_socket_id > 0) {
        close(raw_socket_id);
        raw_socket_id = -1;
    }
    arp_recv_interrupted = 1;
}

int arp_send_to(uint32_t target_ip)
{
    size_t frame_length = 6 + 6 + 2 + ARP_HDRLEN;
    target_ip = htonl(target_ip);
    memcpy(&arphdr.target_ip, &target_ip, 4 * sizeof (uint8_t));

    // ARP header
    memcpy (ether_frame + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof (uint8_t));

    // Send ethernet frame to socket.
    if (sendto (raw_socket_id, ether_frame, frame_length, 0, (struct sockaddr *) &src_device, sizeof(src_device)) <= 0) {
        perror ("arp_send_to failed");
        return -1;
    }
    return 0;
}

void* arp_recv(void *arg)
{
    #define ARPOP_REPLY 2
    uint8_t *recv_ether_frame = (uint8_t*)calloc(IP_MAXPACKET, 1);
    struct arp_hdr *recv_arphdr = (struct arp_hdr *) (recv_ether_frame + 6 + 6 + 2);

    while ( arp_recv_interrupted == 0) {
        if ((recv (raw_socket_id, recv_ether_frame, IP_MAXPACKET, 0)) < 0) {
            if (errno == EINTR) {
                memset (recv_ether_frame, 0, IP_MAXPACKET * sizeof (uint8_t));
                continue;  // Something weird happened, but let's try again.
            } else {
                perror ("recv() failed:");
                return NULL;
            }
        }

        if( (((recv_ether_frame[12] << 8) + recv_ether_frame[13]) != ETH_P_ARP) || (ntohs (recv_arphdr->opcode) != ARPOP_REPLY) ) {
            continue;
        }

        printf("%x:%x:%x:%x:%x:%x\t", recv_ether_frame[6], recv_ether_frame[7], recv_ether_frame[8], recv_ether_frame[9], recv_ether_frame[10], recv_ether_frame[11]);
        printf("%u.%u.%u.%u\n", recv_arphdr->sender_ip[0], recv_arphdr->sender_ip[1], recv_arphdr->sender_ip[2], recv_arphdr->sender_ip[3]);
    }
    return NULL;
}

int calc_next_dest_ip(uint8_t dest_ip[4]) {
    ip_counter++;
    if(ip_counter >= ip_counter_mask)
    {
        ip_counter = 0;
        return -1;
    }

    memcpy(dest_ip, base_addr, 4);
    int i = 0;
    for (i = 0; i < 4; i++)
        dest_ip[3-i] |= (ip_counter << (i*8)) & 0xFF;

    return 0;
}
