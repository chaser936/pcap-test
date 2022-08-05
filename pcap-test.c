#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h> 
#include <libnet.h> //ethernet,ip,tcp 구조체 정보 
#define SIZE_ETHERNET 14
#define TCP_NUM 0x06 

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;
	typedef struct libnet_ethernet_hdr Ether;
	typedef struct libnet_ipv4_hdr Ip;
	typedef struct libnet_tcp_hdr Tcp;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		char *src_ip = NULL;
		char *dst_ip = NULL;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);	

		Ether *ether = (Ether*)packet;
		Ip *ip = (Ip*)(packet+SIZE_ETHERNET);
		
		if((ntohs(ether->ether_type) == ETHERTYPE_IP) && (ip->ip_p == TCP_NUM))
		{


			printf("====== Ethernet Information =====\n");
		
			printf("Dst MAC ==> ");

			for(int i=0;i<6;i++)
			{
				printf("%x:",ether->ether_dhost[i]); //프레임의 바이트는 호스트 컴퓨터의 엔디안과 관계없이 고정된 순서

				if(i==5)
				{	

					printf("%x\n",ether->ether_dhost[i]);
				 }

			}

			 printf("Src MAC ==> ");

		     for(int i=0;i<6;i++)
	   		 {
				 printf("%x:",ether->ether_shost[i]);

				 if(i==5)
				 {

						printf("%x\n",ether->ether_shost[i]);
				 }
				
			 }

			 int SIZE_IP = (ip->ip_hl)*4;

			 src_ip = inet_ntoa(ip->ip_src);
				
			 printf("===== IP Information =====\n");
			 printf("IP SRC ===> %s\n",src_ip);

			 dst_ip = inet_ntoa(ip->ip_dst);
			 printf("IP DST ===> %s\n",dst_ip);


			 Tcp *tcp = (Tcp*)(packet+SIZE_ETHERNET+SIZE_IP);

			 printf("===== TCP Information =====\n");
			 printf("TCP Sport ===> %d\n",ntohs(tcp->th_sport));
		     printf("TCP Dport ===> %d\n",ntohs(tcp->th_dport));

			 int SIZE_TCP = (tcp->th_off)*4;

		     const u_char* payload = (const u_char*)(packet+SIZE_ETHERNET+SIZE_IP+SIZE_TCP);

		     printf("payload ===> ");

			 for(int i=0;i<10;i++)
			 {
				printf("%02x ",payload[i]);
				if(i==9)
					printf("\n");

			}
				

			printf("========================\n");


		}
		else
		{
			printf("TCP 프로토콜을 사용하고 있지 않습니다.\n");
		}



	}

	pcap_close(pcap);
}

