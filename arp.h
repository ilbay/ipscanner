#ifndef ARP_H
#define ARP_H

#include <stdint.h>

int arp_send_init(const char *interface);
int arp_send_to(uint32_t target_ip);
int arp_send_close();
void* arp_recv(void*);
int calc_next_dest_ip(uint8_t dest_ip[4]);

#endif // ARP_H
