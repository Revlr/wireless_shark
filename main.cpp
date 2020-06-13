#include <pcap.h>
#include <iostream>
#include <cstring>

#pragma pack(push, 1)
struct ether_header
{
    unsigned char dst[6];
    unsigned char src[6];
    unsigned short ether_type;
};

struct arp_header
{
    unsigned short  hrd;     // Hardware type : ethernet
    unsigned short  pro;     // Protocol      : IP
    unsigned char   hln;     // Hardware size
    unsigned char   pln;     // Protocal size
    unsigned short  op;      // Opcode replay
    unsigned char   sha[6];  // Sender MAC
    unsigned int   sip;  // Sender IP
    unsigned char   tha[6];  // Target mac
    unsigned int   tip;  // Target IP
};

struct ip_header
{
    unsigned char header_len:4;
    unsigned char version:4;
    unsigned char tos;
    unsigned short total_length;
    unsigned short id;
    unsigned char frag_offset:5;
    unsigned char more_fragment:1;
    unsigned char dont_fragment:1;
    unsigned char reserved_zero:1;
    unsigned char frag_offset1;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned int srcaddr;
    unsigned int destaddr;
};

struct tcp_header
{
    unsigned short source_port;
    unsigned short dest_port;
    unsigned int sequence;
    unsigned int acknowledge;
    unsigned char contorl_bit:4;
    unsigned char data_offset:4;
    unsigned char fin:1;
    unsigned char syn:1;
    unsigned char rst:1;
    unsigned char psh:1;
    unsigned char ack:1;
    unsigned char urg:1;
    unsigned char ecn:1;
    unsigned char cwr:1;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
};
#pragma pack(pop)

int chhex(char ch)
{
    if(isdigit(ch))
        return ch - '0';
    if(tolower(ch) >= 'a' && tolower(ch) <= 'f')
        return ch - 'a' + 10;
    return -1;
}

void stringToHex(unsigned char *dest, const char *source, int bytes_n)
{
    for(bytes_n--; bytes_n >= 0; bytes_n--)
        dest[bytes_n] = 16 * chhex(source[bytes_n*2]) + chhex(source[bytes_n*2 + 1]);
}

void printhex(const u_char* p, int len){
    for (int i = 0; i < len; ++i)
    {
        printf("%02X", p[i]);
    }
    printf("\n\n");
}

void print_mac(unsigned char *mac){
    for (int i = 0; i < 6; ++i)
    {
        printf("%02x", mac[i]);
        if(i!=5) printf(":");
    }
    printf("\n");
}

void print_ip(unsigned int ip){
    for (int i = 0; i < 4; ++i) {
        printf("%d", (ip>>(8*i)) & 0xff);
        if(i!=3) printf(".");
    }
    printf("\n");
}

void print_eth(struct ether_header* eth){
    printf("1. Ethernet\n");
    printf("\t1) Destination Address : ");
    print_mac(eth->dst);
    printf("\t2) Source Address : ");
    print_mac(eth->src);
    printf("\t3) Type : %04X\n", ntohs(eth->ether_type));
}

void print_arp(struct arp_header* arp){
    printf("2. ARP\n");
    printf("\t1) H/W Type : %x \n", ntohs(arp->hrd));
    printf("\t2) Protocol Type : %x \n", ntohs(arp->pro));
    printf("\t3) H/W Size : %x \n", arp->hln);
    printf("\t4) Protocol Size : %x \n", arp->pln);
    printf("\t5) Operation : %x  \n", ntohs(arp->op));
    printf("\t6) Sender MAC Address : ");
    print_mac(arp->sha);
    printf("\t7) Sender IP Address : %x / ", ntohl(arp->sip));
    print_ip(arp->sip);
    printf("\t8) Target MAC Address : ");
    print_mac(arp->tha);
    printf("\t9) Target IP Address : %x /", ntohl(arp->tip));
    print_ip(arp->tip);
}

void print_ip(struct ip_header* ip){
    printf("2. IP\n");
    printf("\t1) Version : %02d \n", ip->version);
    printf("\t2) Header Length : %02x / %d byte\n", ip->header_len, ip->header_len*4);
    printf("\t3) Service Type : %02x / \n", ip->tos);
    printf("\t4) Total Length : %04x / %d bytes : %d bytes payload\n", ntohs(ip->total_length), ntohs(ip->total_length), ntohs(ip->total_length)-(ip->header_len*4));
    printf("\t5) Identification : %04x / %d\n", ntohs(ip->id), ntohs(ip->id));
    printf("\t6) Flags : %d \n", ip->frag_offset1);
    printf("\t\t- Reserve : %d\n", ip->reserved_zero);
    printf("\t\t- Don’t Fragment : %d \n", ip->dont_fragment);
    printf("\t\t- More : %d \n", ip->more_fragment);
    printf("\t7) Offset : %d \n", ip->frag_offset);
    printf("\t8) TTL : %02x / %d hops \n", ip->ttl, ip->ttl);
    printf("\t9) Protocol : %d\n", ip->protocol);
    printf("\t10) Checksum : %04x \n", ntohs(ip->checksum));
    printf("\t11) Source Address : %08x / ", ntohl(ip->srcaddr));
    print_ip(ip->srcaddr);
    printf("\t12) Destination Address : %08x / ", ntohl(ip->destaddr));
    print_ip(ip->destaddr);
}

void print_tcp(struct tcp_header* tcp){
    printf("3. TCP\n");
    printf("\t1) Source Port : %x\n", ntohs(tcp->source_port));
    printf("\t2) Destination Port : %x\n", ntohs(tcp->dest_port));
    printf("\t3) Sequence number : %x\n", ntohl(tcp->sequence));
    printf("\t4) Ack number : %x\n", ntohl(tcp->acknowledge));
    printf("\t5) Header Length : %x\n", tcp->data_offset);
    printf("\t6) Control Bits : %x\n", tcp->contorl_bit);
    printf("\t\t- Urgent : %d\n", tcp->urg);
    printf("\t\t- AcK : %d\n", tcp->ack);
    printf("\t\t- Push : %d\n", tcp->psh);
    printf("\t\t- Reset : %d\n", tcp->rst);
    printf("\t\t- Syn : %d\n", tcp->syn);
    printf("\t\t- Fin : %d\n", tcp->fin);
    printf("\t7) Window Size : %x\n", ntohs(tcp->window));
    printf("\t8) Checksum : %x\n", ntohs(tcp->checksum));
    printf("\t9) Urgent Point : %x\n", ntohs(tcp->urgent_pointer));
}

int main(int argc, char* argv[]) {
    char hexstring[4096]={0};
    unsigned char packet[4096]={0};
  ether_header* eth;
  ip_header* ip;
  tcp_header* tcp;

  while(true){
      printf("Protocol Analyzer\n");
      printf("input your hex string : ");
      scanf("%s",hexstring);
      printf("%lu", sizeof (hexstring));
      stringToHex(packet,hexstring, strlen(hexstring)/2);

      eth = (struct ether_header *)packet;

      if (ntohs(eth->ether_type) == 0x0800) // is_ip
      {
          ip = (struct ip_header *)(packet + 14);
          if (ip->protocol == 6) //is_tcp
          {
              tcp = (struct tcp_header *)(packet + 34);
              printf("\n\n▣ Ethernet Frame(Ethernet Header + IP + TCP)\n\n");
              printhex(packet, 14 + ip->header_len*4 + tcp->data_offset*4);
              print_eth((struct ether_header *)packet);
              print_ip((struct ip_header *)(packet + 14));
              print_tcp((struct tcp_header *)(packet + 34));
          }
          if (ip->protocol == 1) //is_icmp
          {
              printf("\n\n▣ Ethernet Frame(Ethernet Header + IP + ICMP)\n\n");
              printhex(packet, strlen(hexstring)/2);
          }
      }
      if (ntohs(eth->ether_type) == 0x0806) // is_arp
      {
          printf("\n\n▣ Ethernet Frame(Ethernet Header + ARP)\n\n");
          printhex(packet, 42);
          print_eth((struct ether_header *)packet);
          print_arp((struct arp_header *)(packet + 14));
      }
  }
  return 0;
}
