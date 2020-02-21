#ifndef __ARP_TOOLS__
#define __ARP_TOOLS__
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <assert.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

extern u_int32_t target_ip;
extern struct libnet_ether_addr * target_mac;
extern pcap_t * handle;

u_int32_t get_src_ip(libnet_t *);
struct libnet_ether_addr * get_src_mac(libnet_t *);
u_int32_t get_dst_mac(libnet_t *, char *);
void build_arp_request(struct libnet_ether_addr *, u_int32_t *, u_int32_t *, struct libnet_ether_addr *,libnet_t *);
void build_arp_reply(struct libnet_ether_addr *, u_int32_t *, u_int32_t *, struct libnet_ether_addr *,libnet_t *);
void find_target_mac(libnet_t *);
void callback(u_char *, const struct pcap_pkthdr *, const u_char *);
void spoof_addr(libnet_t *, u_int32_t *, u_int32_t *, struct libnet_ether_addr *, struct libnet_ether_addr *);
bool is_reply(struct ether_arp *, u_int32_t target_ip);

#endif
