#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "windivert.h"

#define MAXBUF  0xFFFF

char *memstr(char *srcdata, char *find, int srclen);

int __cdecl main(int argc, char **argv)
{
	HANDLE handle, console;
	UINT i;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	UINT packet_len;
	WINDIVERT_ADDRESS recv_addr, send_addr;
	PWINDIVERT_IPHDR ip_header;
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
	PVOID ppData; // data pointer
	UINT payload_len;
	const char *err_str;
	char *start_point;

	handle = WinDivertOpen("ip && (tcp.DstPort == 80  || tcp.SrcPort == 80) && tcp.PayloadLength > 0", WINDIVERT_LAYER_NETWORK, priority, 0);

	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "error: filter syntax error\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	while (TRUE)
	{
		if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr, &packet_len))
		{
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}

		WinDivertHelperParsePacket(packet, packet_len, &ip_header, &ipv6_header, &icmp_header, &icmpv6_header, &tcp_header,
			&udp_header, NULL, &payload_len);

		if (ip_header != NULL)
		{
			UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
			UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
			printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u ",
				src_addr[0], src_addr[1], src_addr[2], src_addr[3],
				dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
		}

		if (tcp_header != NULL)
		{
			printf("tcp.SrcPort=%u tcp.DstPort=%u tcp.Flags=",
				ntohs(tcp_header->SrcPort), ntohs(tcp_header->DstPort));
			if (tcp_header->Fin)
			{
				fputs("[FIN]", stdout);
			}
			if (tcp_header->Rst)
			{
				fputs("[RST]", stdout);
			}
			if (tcp_header->Urg)
			{
				fputs("[URG]", stdout);
			}
			if (tcp_header->Syn)
			{
				fputs("[SYN]", stdout);
			}
			if (tcp_header->Psh)
			{
				fputs("[PSH]", stdout);
			}
			if (tcp_header->Ack)
			{
				fputs("[ACK]", stdout);
			}
			putchar(' ');
			putchar('\n');

			if (recv_addr.Direction == 0) //outbound
			{
				char out_search_string[] = "gzip";
				char out_replace_string[] = "    ";

				start_point = memstr(packet, &out_search_string, payload_len);
				if (start_point == NULL)
				{
					WinDivertHelperCalcChecksums((PVOID)packet, packet_len, 0);

					if (!WinDivertSend(handle, packet, packet_len, &recv_addr, NULL))
					{
						fprintf(stderr, "warning: failed to send original_packet 3 (%d)\n",
							GetLastError());
					}
					continue;
				}

				else
				{
					memcpy(start_point, &out_replace_string, sizeof(out_replace_string) - 1);

					WinDivertHelperCalcChecksums((PVOID)packet, packet_len, 0);

					if (!WinDivertSend(handle, (PVOID)packet, packet_len, &recv_addr, NULL))
					{
						fprintf(stderr, "warning: failed to send new_packet (%d)\n",
							GetLastError());
					}
					continue;
				}
			}

			if (recv_addr.Direction == 1) // inbound
			{
				char in_search_string[] = "Michael";
				char in_replace_string[] = "Gilbert";

				start_point = memstr(packet, &in_search_string, payload_len);

				if (start_point == NULL)
				{
					WinDivertHelperCalcChecksums((PVOID)packet, packet_len, 0);

					if (!WinDivertSend(handle, packet, packet_len, &recv_addr, NULL))
					{
						fprintf(stderr, "warning: failed to send original_packet 4 (%d)\n",
							GetLastError());
					}
					continue;
				}

				else
				{
					memcpy(start_point, &in_replace_string, sizeof(in_replace_string) - 1);

					WinDivertHelperCalcChecksums((PVOID)packet, packet_len, 0);

					if (!WinDivertSend(handle, (PVOID)packet, packet_len, &recv_addr, NULL))
					{
						fprintf(stderr, "warning: failed to send new_packet (%d)\n",
							GetLastError());
					}
					continue;
				}
			}
		}
	}
}

char *memstr(char *srcdata, char *find, int srclen)
{
	char *p;
	int findlen = strlen(find);
	for (p = srcdata; p <= (srcdata + srclen - findlen); p++)
	{
		if (memcmp(p, find, findlen) == 0)
			return p;
	}
	return NULL;
}
