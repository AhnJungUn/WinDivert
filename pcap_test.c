#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <libnet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct libnet_ethernet_hdr *ethhdr;
    struct libnet_ipv4_hdr *iphdr;
    struct libnet_tcp_hdr *tcphdr;
   
    unsigned short ether_type;
    unsigned short ip_type;    
    int chcnt =0;
    int length=pkthdr->len;

    ethhdr = (struct libnet_ethernet_hdr *)packet;
    packet += sizeof(struct libnet_ethernet_hdr);
    
    printf("ethernet Src Mac  : %s\n",(char*)ether_ntoa(ethhdr->ether_shost));
    printf("ethernet Dst Mac  : %s\n\n",(char*)ether_ntoa(ethhdr->ether_dhost));	
    
    ether_type = ntohs(ethhdr->ether_type); 

    if (ether_type == ETHERTYPE_IP) 
    {
        iphdr = (struct libnet_ipv4_hdr *)packet;
        printf("IP Packet\n");
        printf("Src IP  : %s\n", inet_ntoa(iphdr->ip_src)); 
        printf("Dst IP  : %s\n\n", inet_ntoa(iphdr->ip_dst));
    }
    else
    {
	printf("No IP_Packet \n\n");
	return;
    }

    ip_type=iphdr->ip_p;
	
    if(ip_type == 0x06)
    {
	packet += iphdr->ip_hl * 4; 
	tcphdr = (struct libnet_tcp_hdr *)(packet); 
	printf("TCP Packet\n");
        printf("Src Port : %d\n" , ntohs(tcphdr->th_sport));
        printf("Dst Port : %d\n\n" , ntohs(tcphdr->th_dport));
	    
	packet += tcphdr->th_off * 4;
	length = length - sizeof(struct libnet_ethernet_hdr) - iphdr->ip_hl - tcphdr->th_off;   
	
	printf("DATA \n");    
	while(length--)
        {
             printf("%02x", *(packet++)); 
             if ((++chcnt % 16) == 0) 
                 printf("\n");
        }
	printf("\n\n");
     }
     else
     {
     	printf("No TCP_Packet \n");
	return;
     }	
}

int main(int argc, char **argv)
{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd;  // packet capture descriptor
    
    dev = pcap_lookupdev(errbuf);
    
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
  
    pcd = pcap_open_live(dev, BUFSIZ, 1/*PROMISCUOUS*/, -1, errbuf);
    
    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }    

    pcap_loop(pcd, 0, callback, NULL);
}
