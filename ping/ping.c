#include <stdio.h>
#include <sys/types.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <sys/time.h>
//#include <linux/time.h>
//#include <linux/in.h>
#include <errno.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <signal.h>
#include <setjmp.h>
#include <netdb.h>


// main control block
struct ping_cb {
	// config
	union {
		struct sockaddr addr;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct sockaddr_storage superset;
	};
	int ttl;
	long int interval;
	char *remote_address;

	// internal values
	int fd;
	struct timeval send_time;
	uint16_t id;
	uint16_t seq;

	// stats
	int pkts_out, pkts_rcvd;
	float min, avg, max, std_dev;
};
jmp_buf handle_signal;

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
	exit(EXIT_FAILURE);
}

int ip_hdr_size(uint8_t *payload, int len)
{
	if((payload[0]&0xf0) == 0x40) { //IPv4
		return (payload[0] & 0x0f) * 4;
	}

	//IPv6
	if((payload[0]&0xf0) == 0x60) { //IPv6
		//TODO add support for muliple IPv6 headers.
		struct ipv6hdr *ip6h = (struct ipv6hdr*)payload;
		return ntohs(ip6h->payload_len);
	}

	return 0;
}

void print_addr(struct sockaddr *sin)
{
	char addr_str[INET6_ADDRSTRLEN];
	int family = sin->sa_family;
	void *addr_ptr = family == AF_INET ?
			(void*)&(((struct sockaddr_in*)sin)->sin_addr) :
			(void*)&(((struct sockaddr_in6*)sin)->sin6_addr);

	memset(addr_str, 0, INET6_ADDRSTRLEN*sizeof(char));
	if(inet_ntop(family, addr_ptr, addr_str,
				INET6_ADDRSTRLEN) == NULL){
		printf("inet_ntop error: %m\n");
		exit(EXIT_FAILURE);
	}
	printf("Sin addr %s\n", addr_str);
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

void update_stats(struct ping_cb *pc, struct timeval *tv)
{
	float diff = 0; //in milliseconds
	float new_avg = 0;

	diff = (tv->tv_sec - pc->send_time.tv_sec)*1000000;
	diff += tv->tv_usec;
	diff -= pc->send_time.tv_usec;
	if(diff <0) {
		printf("Error calculating the diff\n");
		return;
	}

	if(pc->min > diff)
		pc->min = diff;
	if(pc->max < diff)
		pc->max = diff;

	new_avg = (pc->avg*pc->pkts_rcvd + diff)/(pc->pkts_rcvd + 1);
	pc->std_dev = ((pc->std_dev + pc->avg*pc->avg)*pc->pkts_rcvd + diff*diff)/(pc->pkts_rcvd + 1)
				- new_avg*new_avg;
	pc->avg = new_avg;
	pc->pkts_rcvd++;
}

void print_stats(struct ping_cb *pc)
{

	printf("\n--- %s ping statistics\n", pc->remote_address);

	printf("%d ping packets sent, %d received, %.2f%c packet loss\n",
			pc->pkts_out, pc->pkts_rcvd,
			100.0 - (100.0*pc->pkts_rcvd)/pc->pkts_out, '%');

	if(pc->pkts_rcvd == 0) {
		printf("rtt stats: avg NA, min NA, max NA, mdev NA\n");
	} else {
		printf("rtt stats: avg %.3fms, min %.3fms, max %.3fms, mdev %.3fms\n",
				pc->avg/1000, pc->min/1000, pc->max/1000, pc->std_dev/1e6);
	}
	exit(EXIT_SUCCESS);
}

void sigint_handler (int arg)
{
	longjmp(handle_signal, 1);
}

int send_ping(struct ping_cb *pc)
{
	int rc = 0;
	uint8_t payload[30];

	socklen_t slen = sizeof(struct sockaddr_in);
	if(pc->sin.sin_family == AF_INET6)
		slen = sizeof(struct sockaddr_in6);

	memset(payload, 0, 30*sizeof(uint8_t));
	if(pc->sin.sin_family == AF_INET) {
		struct icmphdr *hdr;

		hdr = (struct icmphdr *) payload;
		hdr->type = ICMP_ECHO;
		hdr->code = 0;
		hdr->un.echo.id = htons(pc->id);
		hdr->un.echo.sequence = htons(pc->seq);
		hdr->checksum = calc_checksum(payload, 30);
	} else {
		struct icmp6hdr *hdr6;
		hdr6 = (struct icmp6hdr*) payload;
		hdr6->icmp6_type = ICMPV6_ECHO_REQUEST;
		hdr6->icmp6_code = 0;
		hdr6->icmp6_dataun.u_echo.identifier = htons(pc->id);
		hdr6->icmp6_dataun.u_echo.sequence = htons(pc->seq);
		hdr6->icmp6_cksum = calc_checksum(payload, 30);
	}

	if(gettimeofday(&pc->send_time, NULL) < 0) {
		printf("gettimeofday() failed: %m\n");
		exit(EXIT_FAILURE);
	}

	//print_addr(&pc->addr);
	//print_payload(payload, 30);
	rc = sendto(pc->fd, payload, 30, MSG_DONTWAIT, &pc->addr, slen);
	if( rc < 0) {
		printf("sendto failed %m\n");
	}
	pc->pkts_out++;

	return rc;
}

int check_response(struct ping_cb *pc, struct msghdr *msg, int len, int *ttl)
{
	uint8_t *payload = msg->msg_iov->iov_base;
	uint8_t ipversion = payload[0]&0xf0;
	struct cmsghdr *cmsg;
	//if(ipversion != 0x40 && ipversion != 0x60)
	//	return -1; //non-ip packet

	if(pc->sin.sin_family==AF_INET) {
		if(ipversion != 0x40)
			return -1;
		struct iphdr* iph = (struct iphdr*)payload;
		struct icmphdr *hdr = (struct icmphdr*)
					(payload + ip_hdr_size(payload, len));

		if(hdr->type == ICMP_TIME_EXCEEDED) {
			int offset = ip_hdr_size(payload, len)
					+ sizeof(struct icmphdr);
			hdr = (struct icmphdr*)(payload + offset +
						ip_hdr_size(payload + offset,
							    len - offset));
			if(hdr->un.echo.id == htons(pc->id) &&
			   hdr->un.echo.sequence == htons(pc->seq)) {
				return ICMP_TIME_EXCEEDED;
			}
			return -1;
		}

		if(hdr->type == ICMP_ECHOREPLY &&
		   hdr->un.echo.id == htons(pc->id) &&
		   hdr->un.echo.sequence == htons(pc->seq)) {
			*ttl = iph->ttl;
			return ICMP_ECHOREPLY;
		}

		return -1;

	} else {
		struct icmp6hdr *hdr = (struct icmp6hdr*) payload;
					//(payload + ip_hdr_size(payload, len));
		for(cmsg =CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
			if(cmsg->cmsg_level == SOL_IPV6 &&
			   cmsg->cmsg_type == IPV6_HOPLIMIT) {
				memcpy(ttl, CMSG_DATA(cmsg), sizeof(int));
			}
		}

		if(hdr->icmp6_type == ICMPV6_EXC_HOPLIMIT) {
			int offset = sizeof(struct icmp6hdr);
			hdr = (struct icmp6hdr*)(payload + offset
						 + ip_hdr_size(payload + offset,
								len - offset));
			if(hdr->icmp6_type == ICMPV6_ECHO_REPLY &&
			   hdr->icmp6_dataun.u_echo.identifier == htons(pc->id) &&
			   hdr->icmp6_dataun.u_echo.sequence == htons(pc->seq)) {
				return ICMP_TIME_EXCEEDED;
			}
			return -1;
		}

		if(hdr->icmp6_type == ICMPV6_ECHO_REPLY &&
		   hdr->icmp6_dataun.u_echo.identifier == htons(pc->id) &&
		   hdr->icmp6_dataun.u_echo.sequence == htons(pc->seq)) {
			return ICMP_ECHOREPLY;
		}

		return -1;
	}
}

void recv_ping(struct ping_cb *pc)
{
	int rc = 0;
	fd_set readfds;
	struct timeval tv;
	uint8_t payload[1500];
	uint8_t cbuf[1000];
	//struct icmphdr *hdr;
	struct iovec iov;
	struct msghdr msg;

	iov.iov_base = payload;
	iov.iov_len = 1500;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = 1000;
	msg.msg_flags = 0;

	memset(payload, 0, 1500);
	memset(&tv, 0, sizeof(struct timeval));
	tv.tv_sec = pc->interval/1000;
	tv.tv_usec = (long)((pc->interval%1000) * 1000);

	FD_ZERO(&readfds);
	FD_SET(pc->fd, &readfds);

	while((rc=select(pc->fd + 1, &readfds, NULL, NULL, &tv)) > 0) {
		struct timeval rcv_tv;
		int ttl = 0;
		memset(&rcv_tv, 0, sizeof(struct timeval));

		if(!FD_ISSET(pc->fd, &readfds)) {
			continue;
		}

		//received a response.
		memset(payload, 0, 1500);
		rc = recvmsg(pc->fd, &msg, MSG_DONTWAIT);
		if(rc <= 0) {
			continue;
		}
		gettimeofday(&rcv_tv, NULL);

		switch(check_response(pc, &msg, rc, &ttl)) {
		case ICMP_TIME_EXCEEDED:
		{
			printf("TTL exceeded\tseq=%d\n", pc->seq);
			if(tv.tv_sec)
				sleep(tv.tv_sec);
			usleep(tv.tv_usec);
			return;
		}
		break;

		case ICMP_ECHOREPLY:
		{
			float diff = 0;
			diff = (rcv_tv.tv_sec - pc->send_time.tv_sec)*1000000;
			diff += rcv_tv.tv_usec;
			diff -= pc->send_time.tv_usec;
			printf("received reply\t seq=%d, ttl=%d, rtt=%.3fms\n",
					pc->seq, ttl, diff/1000);
			update_stats(pc, &rcv_tv);
			if(tv.tv_sec)
				sleep(tv.tv_sec);
			usleep(tv.tv_usec);
			return;
		}
		break;

		default:
			continue;
		}
	}

	if(rc == 0) {
		//timeout
		printf("timeout\t seq=%d\n", pc->seq);
	}
}

void get_pc_sockaddr(struct ping_cb *pc, int family)
{
	int rc=0;
	struct addrinfo hints, *result = NULL;
	char addr_str[INET6_ADDRSTRLEN];
	void *addr_ptr = family == AF_INET ? (void*)&(pc->sin.sin_addr) :
					     (void*)&(pc->sin6.sin6_addr);

	rc = inet_pton(family, pc->remote_address, addr_ptr);
	if( rc == 1) {
		/* inet_pton worked */
		return;
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = family;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_protocol = IPPROTO_ICMP;

	rc = getaddrinfo(pc->remote_address, NULL, &hints, &result);
	if(rc != 0) {
		printf("Unable to resolve %s error: %s\n",
				pc->remote_address, gai_strerror(rc));
		exit(EXIT_FAILURE);
	}

	memcpy(&pc->sin, result->ai_addr, sizeof(struct sockaddr));

	memset(addr_str, 0, INET6_ADDRSTRLEN*sizeof(char));
	if(inet_ntop(family, result->ai_addr, addr_str,
				INET6_ADDRSTRLEN) == NULL){
		printf("inet_ntop error: %m\n");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(result);

	memset(addr_str, 0, INET6_ADDRSTRLEN*sizeof(char));
	if(inet_ntop(family, addr_ptr, addr_str,
				INET6_ADDRSTRLEN) == NULL){
		printf("inet_ntop error: %m\n");
		exit(EXIT_FAILURE);
	}
	printf("%s resolved to %s\n", pc->remote_address, addr_str);
}

void read_config(struct ping_cb *pc, int argc, char *argv[], char* rem_addr)
{
	int rc = 0, argidx = 0;

	if(argc < 0 || argc > 5) {
		printhelp();
	}

	//set a few default options
	pc->min = 1e10;
	pc->sin.sin_family = AF_INET;
	pc->ttl = 50;
	pc->interval = 1000; // 1 second
	pc->seq = 0;
	pc->id = (uint16_t) getpid();

	//read the configs and change ping_cb's values
	while(argidx < argc) {
		if(strcmp(argv[argidx], "-6") == 0) { // -v6
			pc->sin.sin_family = AF_INET6;
			argidx++;
			continue;
		}

		if(strcmp(argv[argidx], "-4") == 0) { // -v4
			pc->sin.sin_family = AF_INET;
			argidx++;
			continue;
		}

		if(strcmp(argv[argidx], "-t") == 0) { // ttl
			int ttl = 0;
			char *endptr = NULL;
			if(argidx +1 >= argc) {
				printf("TTL value missing\n");
				printhelp();
			}

			errno = 0;
			ttl = (int)strtol(argv[argidx+1], &endptr, 10);
			if(endptr == argv[argidx+1] || errno != 0 ||
			   ttl < 0 || ttl > 0xff) {
				printf("TTL value invalid\n");
				printhelp();
			}

			pc->ttl = ttl;
			argidx += 2;
			continue;
		}

		if(strcmp(argv[argidx], "-i") == 0) { // interval
			long int interval = 0;
			char *endptr = NULL;
			if(argidx + 1 >= argc) {
				printf("Interval value missing\n");
				printhelp();
			}

			errno = 0;
			interval = strtol(argv[argidx+1], &endptr, 10);
			if(endptr == argv[argidx+1] || errno != 0 || interval<0) {
				printf("Interval value invalid\n");
				printhelp();
			}
			if(interval < 100) {
				printf("Warning: Interval less than 100ms. "
					"Ping does not support multiple packets in air.\n"
					"Packets may incorrectly be classified as timeouts.\n");
			}

			pc->interval = interval;
			argidx += 2;
			continue;
		}

		printf("Invalid Parameter %s\n", argv[argidx]);
		printhelp();
	}

	pc->remote_address = (char*)calloc(strlen(rem_addr)+1, sizeof(char));
	strncpy(pc->remote_address, rem_addr, strlen(rem_addr));
	get_pc_sockaddr(pc, pc->sin.sin_family);

	//everything ready, open a socket
	pc->fd = socket(pc->sin.sin_family, SOCK_RAW | SOCK_NONBLOCK,
			pc->sin.sin_family == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6);
	if(pc->fd == -1) {
		printf("Unable to open RAW socket: %m\n");
		exit(EXIT_FAILURE);
	}

	////set a ICMP filter to only receive ICMP ECHO & TTL exceeded messages
	if(pc->sin.sin_family == AF_INET) {
		uint32_t flags = ~(1<<ICMP_ECHOREPLY | 1<<ICMP_TIME_EXCEEDED);
		rc = setsockopt(pc->fd, SOL_RAW, ICMP_FILTER, &flags,
				sizeof(flags));
		if(rc == -1) {
			printf("Unable to set ICMP_FILTER: %m");
			exit(EXIT_FAILURE);
		}
	} else {
		int set = 1;
		rc = setsockopt(pc->fd, IPPROTO_IPV6, IPV6_HOPLIMIT,
				&set, sizeof(set));
		if(rc == -1) {
			//printf("Unable to set IPV6_HOPLIMIT\n");
		}

		rc = setsockopt(pc->fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
				&set, sizeof(set));
		if(rc == -1) {
			//printf("Unable to set IPV6_RECVHOPLIMIT\n");
		}
	}

	////set ttl
	{
		uint32_t ttl = pc->ttl;
		int optname = IP_TTL;
		int level = IPPROTO_IP;
		if(pc->sin.sin_family == AF_INET6) {
			optname = IPV6_UNICAST_HOPS;
			level = SOL_IPV6;
		}
		rc = setsockopt(pc->fd, level, optname, &ttl, sizeof(ttl));
		if(rc == -1) {
			printf("Unable to set IP_TTL: %m");
			exit(EXIT_FAILURE);
		}
	}

}


int main(int argc, char* argv[])
{
	struct ping_cb *pc = NULL;

	pc = (struct ping_cb*) calloc(1, sizeof(struct ping_cb));
	if(pc == NULL) {
		printf("Unable to Allocate memory: %m");
		exit(EXIT_FAILURE);
	}

	if(argc == 2 &&
	   (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
		printhelp();
	}

	// read arguments, fill up config.
	read_config(pc, argc - 2, argv + 1, argv[argc-1]);

	//add signal handler
	signal(SIGINT, sigint_handler);
	if(setjmp(handle_signal) == 1)
		print_stats(pc);
	
	while(1) {
		pc->seq++;
		if(send_ping(pc) < 0) {
			sleep(pc->interval/1000);
			usleep(pc->interval%1000);
		} else {
			recv_ping(pc);
		}
	}

}
