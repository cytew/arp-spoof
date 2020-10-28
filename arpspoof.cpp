#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h> 
#include <sys/socket.h>
#include <sys/types.h>

#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <pcap.h>

#include "mac.h"
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"

#include "arpspoof.h"

#define MAC_ALEN 6

extern Mac my_Mac;
extern Ip my_Ip;

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

Mac GetMyMacAddr(const char* ifname){ //https://tttsss77.tistory.com/138
    
    struct ifreq ifr;
    int sockfd, ret;
	uint8_t macAddr[MAC_ALEN];
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        fprintf(stderr, "Fail to get interface MAC address - socket() failed - %m\n");
        exit(0);
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0) {
        fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sockfd);
        exit(0);
    }

    close(sockfd);
    
    memcpy(macAddr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);
    return macAddr;
}


Ip GetMyIp(const char* ifname){
    struct ifreq ifr;
    int sockfd, ret;
    char ipAddr[40];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        fprintf(stderr, "Fail to get interface MAC address - socket() failed - %m\n");
        exit(0);
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
    if (ret < 0) {
        fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFADDR) failed - %m\n");
        close(sockfd);
        exit(0);
    }

    close(sockfd);
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipAddr, sizeof(struct sockaddr));
    //change network info to char LE
	//sockaddr: 2byte family 14byte IP+Port

    return Ip(ipAddr);
}


Mac GetMacFromIP(pcap_t* handle, Ip ipAddr){
    
    //request_packet
    EthArpPacket req_packet;

	req_packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	req_packet.eth_.smac_ = my_Mac;// attacker mac
	req_packet.eth_.type_ = htons(EthHdr::Arp);

	req_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	req_packet.arp_.pro_ = htons(EthHdr::Ip4);
	req_packet.arp_.hln_ = Mac::SIZE;
	req_packet.arp_.pln_ = Ip::SIZE;
	req_packet.arp_.op_ = htons(ArpHdr::Request);
	req_packet.arp_.smac_ = my_Mac; // attacker mac
	req_packet.arp_.sip_ = htonl(my_Ip);  
	req_packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); 
	req_packet.arp_.tip_ = htonl(ipAddr);

    //send packet to get sender MAC addr
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&req_packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

    //reply_packet
    EthArpPacket* rep_packet=nullptr;

    while (1) {
        struct pcap_pkthdr* header;
	    const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);//get the latest packet data
        if (res == 0) continue;
        if (res == -1 || res == -2) { // -1=error while reading packet -2=EOF 0=timeout
            printf ("Getting last packet Error!\n");
			break;
        }
        rep_packet = (EthArpPacket*)packet;
        if(rep_packet->eth_.type() != EthHdr::Arp)
            continue;  // check if it is Arp packet if not pass
        if(rep_packet->arp_.op() != ArpHdr::Reply)
            continue;  // check if it is Arp reply if not pass
        if(rep_packet->arp_.sip() != ipAddr)
            continue;  // check if it is same as given IP Address if not pass
        
        break;
    }
    return Mac(rep_packet->arp_.smac_);
}

