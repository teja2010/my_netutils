#include <stdio.h>
#include <sys/types.h>
#include <linux/icmp.h>
#include <sys/time.h>
//#include <linux/time.h>
//#include <linux/in.h>
#include <linux/ip.h>
#include <linux/in6.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>


// main control block
struct ping_cb {
	// config
	union {
		struct sockaddr addr;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	};
	int ttl;
	int interval;

	// internal values
	int fd;
	struct timeval send_time;
	uint16_t id;
	uint16_t seq;

	// stats
	int pkts_out, pkts_rcvd;
	float min, avg, max, mdev;
};

uint16_t calc_checksum(uint8_t *payload, int len)
{
	//rfc 1071
	uint32_t sum = 0;
	int idx = 0;
	while((len-idx)>1) {
		sum += payload[idx]*256 + payload[idx+1];
		idx += 2;
	}
	if(len-idx == 1) {
		sum += payload[idx]*256;
	}

	while(sum > 0xffff) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return htons(~(uint16_t)sum); // complement of sum
}

void printhelp()
{
	printf("ping Usage:\n");
	printf("ping [-4] [-t ttl] [-i interval(milliseconds)] IPv4_address\n");
	printf("ping  -6  [-t ttl] [-i interval(milliseconds)] IPv6_address\n");
}

int ip_hdr_size(uint8_t *payload, int len)
{
	if((payload[0]&0xf0) == 0x40) {
		return (payload[0] & 0x0f) * 4;
	}

	//TODO add IPv6 support
	return 0;
}

void print_payload(uint8_t *payload, int len)
{
	int i= 0;
	printf("---\n");
	for(i=0; i<len; i++) {
		printf("%x ", payload[i]);
		if(i%8==7)
			printf("\n");
	}
	printf("\n");
}

int send_ping(struct ping_cb *pc)
{
	int rc = 0;
	uint8_t payload[30];
	struct icmphdr *hdr;
	socklen_t slen = sizeof(struct sockaddr);

	memset(payload, 0, 30*sizeof(uint8_t));
	hdr = (struct icmphdr *) payload;
	hdr->type = ICMP_ECHO;
	hdr->code = 0;
	hdr->un.echo.id = htons(pc->id);
	hdr->un.echo.sequence = htons(pc->seq);
	hdr->checksum = calc_checksum(payload, 30);

	if(gettimeofday(&pc->send_time, NULL) < 0) {
		printf("gettimeofday() failed: %m\n");
		exit(EXIT_FAILURE);
	}

	rc = sendto(pc->fd, payload, 30, MSG_DONTWAIT, &pc->addr, slen);
	if( rc < 0) {
		printf("sendto failed %m\n");
	}

	return rc;
}

void recv_ping(struct ping_cb *pc)
{
	int rc = 0;
	fd_set readfds;
	struct timeval tv;
	uint8_t payload[1500];
	struct iphdr *iph;
	struct icmphdr *hdr;

	memset(payload, 0, 1500);
	memset(&tv, 0, sizeof(struct timeval));
	tv.tv_sec = pc->interval/1000;
	tv.tv_usec = (long)((pc->interval%1000) * 1000);

	FD_ZERO(&readfds);
	FD_SET(pc->fd, &readfds);

	while((rc=select(pc->fd + 1, &readfds, NULL, NULL, &tv)) > 0) {

		if(!FD_ISSET(pc->fd, &readfds)) {
			continue;
		}

		//received a response.
		memset(payload, 0, 1500);
		rc = recv(pc->fd, payload, 1500, 0);
		if(rc <= 0) {
			//printf("ICMP recv failed: %m");
			continue;
		}

		//print_payload(payload, rc);
		iph = (struct iphdr*)payload;
		hdr = (struct icmphdr*)(payload + ip_hdr_size(payload, rc));
		if(hdr->type == ICMP_TIME_EXCEEDED) {
			int offset = ip_hdr_size(payload, rc)
					+ sizeof(struct icmphdr);
			hdr = (struct icmphdr*)(payload + offset +
						ip_hdr_size(payload + offset,
							    rc - offset));
			if(hdr->un.echo.sequence != htons(pc->seq) ||
			   hdr->un.echo.id != htons(pc->id)) {
				continue;
			}

			printf("TTL exceeded\tseq=%d\n", pc->seq);
			sleep(tv.tv_sec);
			usleep(tv.tv_usec);
			return;
		}


		if(hdr->type != ICMP_ECHOREPLY ||
		   hdr->un.echo.sequence != htons(pc->seq) ||
		   hdr->un.echo.id != htons(pc->id)) {
			continue;
		}

		printf("received reply\t seq=%d, ttl=%d\n", pc->seq, iph->ttl);
		sleep(tv.tv_sec);
		usleep(tv.tv_usec);
		return;
	}

	if(rc == 0) {
		//timeout
		printf("timeout\t seq=%d\n", pc->seq);
	}

}

void read_config(struct ping_cb *pc, int argc, char *argv[])
{
	int rc = 0, argidx = 0;

	if(argc == 0) {
		printhelp();
		exit(EXIT_FAILURE);
	}

	//set a few default options
	pc->sin.sin_family = AF_INET;
	pc->ttl = 50;
	pc->interval = 1000; // 1 second
	pc->seq = 0;
	pc->id = (uint16_t) getpid();


	//read the configs and change ping_cb's values
	//TODO

	if(pc->sin.sin_family == AF_INET) {
		rc = inet_pton(AF_INET, argv[argidx], &pc->sin.sin_addr);
		if( rc != 1) {
			printf("Error Parsing the Address: %m");
			exit(EXIT_FAILURE);
		}
	}

	//everything ready, open a socket
	pc->fd = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP);
	if(pc->fd == -1) {
		printf("Unable to open RAW socket: %m\n");
		exit(EXIT_FAILURE);
	}

	//{
	//	struct timeval tv;
	//	socklen_t slen = sizeof(struct timeval);

	//	memset(&tv, 0, sizeof(struct timeval));
	//	tv.tv_usec = pc->interval/1000;
	//	tv.tv_usec = (long)((pc->interval%1000) * 1000);
	//	rc = setsockopt(pc->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, slen);
	//	if(rc == -1) {
	//		printf("Unable to set SO_RCVTIMEO: %m");
	//		exit(EXIT_FAILURE);
	//	}
	//}

	//set a ICMP filter to only receive ICMP ECHO & TTL exceeded messages
	{
		uint32_t flags = ~(1<<ICMP_ECHOREPLY | 1<<ICMP_TIME_EXCEEDED);
		rc = setsockopt(pc->fd, SOL_RAW, ICMP_FILTER, &flags,
				sizeof(flags));
		if(rc == -1) {
			printf("Unable to set ICMP_FILTER: %m");
			exit(EXIT_FAILURE);
		}
	}

	//set ttl
	{
		uint32_t ttl = pc->ttl;
		rc = setsockopt(pc->fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
		if(rc == -1) {
			printf("Unable to set IP_TTL: %m");
			exit(EXIT_FAILURE);
		}
	}

	//create a timerfd
	//{
	//	pc->timer_fd = timerfd_create(CLOCK_REALTIME, TFD_NONBLOCK);
	//	if(pc->timer_fd < 0) {
	//		printf("Unable to create a timerfd: %m");
	//		exit(EXIT_FAILURE);
	//	}
	//}
}


int main(int argc, char* argv[])
{
	struct ping_cb *pc = NULL;

	pc = (struct ping_cb*) calloc(1, sizeof(struct ping_cb));
	if(pc == NULL) {
		printf("Unable to Allocate memory: %m");
		exit(EXIT_FAILURE);
	}

	// read arguments, fill up config.
	read_config(pc, argc - 1, argv + 1);
	
	while(1) {
		pc->seq++;
		if(send_ping(pc) < 0)
			usleep(pc->interval*1000);
		else {
			recv_ping(pc);
		}
	}
}
