#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include "arp.h"

static void reverse_array(uint8_t *array, int size) {
    uint8_t temp;
    int i = 0;
    for(i = 0; i < size/2; i++) {
        temp = array[size-i-1];
        array[size-i-1] = array[i];
        array[i] = temp;
    }
}

int main()
{
    uint8_t possible_ip[4];
    uint32_t target_ip;
    arp_send_init("enp2s0");

    pthread_t thread;
    pthread_create(&thread, NULL, arp_recv, NULL);

    while( calc_next_dest_ip(possible_ip) >= 0 ) {
        reverse_array(possible_ip, 4);
        memcpy(&target_ip, possible_ip, 4);
        arp_send_to(target_ip);
    }

    sleep(1);
    arp_send_close();
    pthread_join(thread, NULL);
    return 0;
}
