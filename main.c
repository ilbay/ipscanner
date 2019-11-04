#include <stdio.h>
#include <stdint.h>
#include "arp.h"

int main()
{
    unsigned char target_ip_[4] = {1, 2, 168, 192};
    uint32_t target_ip;
    memcpy(&target_ip, target_ip_, 4);
    arp_send_init("enp2s0");
    arp_send_to(target_ip);
    arp_send_close();
    return 0;
}
