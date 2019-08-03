#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include "sendarp_header.h"

unsigned char sender_mac_address[6];
unsigned char target_mac_address[6] = {0};
const char arp_demo[] = "\x00\x01\x08\x00\x06\x04\x00\x02\xbc\x54\x51\xba\x34\x22\xc0\xa8" \
                         "\x2b\x01\x98\x2c\xbc\x6d\x42\x8c\xc0\xa8\x2b\xea";

int send_packet();
void get_mac();

int main()
{
    int j;
    get_mac();
    for (j = 0; j < 6; ++j)
        printf(" %02x", (unsigned char) sender_mac_address[j]);
    putchar('\n');

    send_packet();
}

//interface,interface_name
int send_packet(){
    pcap_t *fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    unsigned char packet[100];
    int i;
    pcap_if_t *d;
    pcap_if_t *alldevs;

    if(pcap_findalldevs(&alldevs, errbuf) == -1){
        fprintf(stderr, "Error in pcap_findalldevs :%s\n", errbuf);
        exit(1);
    }

    for (d=alldevs;d;d=d->next)
    {
        printf("%d. %s", ++i, d->name);
    if(d->description)
        printf("(%s)\n",d->description);
    else
        printf("(No description Available)\n");
    }
    d = alldevs;


    /* Open the output device */
    if ( (fp= pcap_open_live(d->name,     		// name of the device(interface_name)
                        100,                // portion of the packet to capture (only the first 100 bytes)
                        0, 					//PCAP_OPENFLAG_PROMISCUOUS
                        1000,               // read timeout
                        errbuf              // error buffer
                        ) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
        return -1;
    }

    /* Make ethernet header */
    int pointer = 0;
    memcpy(packet + pointer, target_mac_address, 6);
    memcpy(packet + pointer + 6, sender_mac_address, 6);
    memcpy(packet + pointer + 12, "\x08\x06", 2);

    /* Make ARP header */
    pointer += 14;
    memcpy(packet + pointer, arp_demo, 28);
    for(i=29;i<100;i++)
    {
        packet[i]=i%256;
    }

    /* Send down the packet */
    if (pcap_sendpacket(fp, packet, 100 /* size */) != 0)
    {
        fprintf(stderr,"\nError sending the packet:  \n", pcap_geterr(fp));
        return 1;
    }

    return 0;
}

void get_mac(){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, "ens33");
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {

    memcpy(sender_mac_address, s.ifr_addr.sa_data, 6);

    //for (int i = 0; i < 6; ++i)
    //  printf(" %02x", (unsigned char) sender_mac_address[i]);
  }
}
