#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>


int sockaddr_init(const char* address, int port, struct sockaddr* sockaddr) {
  struct sockaddr_in addr_in;
  addr_in.sin_family = AF_INET;

  if (inet_aton(address, &addr_in.sin_addr) == 0) {
    fprintf(stderr,"Invalid IPv4 Address.\n");
    return -1;
  }

  if(port < 49152 || port > 65535) {
    fprintf(stderr, "You must use private ports (49152-65535)\n");
    return -1;
  }

  addr_in.sin_port = htons(port);
  *sockaddr = *((struct sockaddr *) &addr_in);
  return 0;
}



int main(int argc, char* argv[]) {
  if(argc < 4) {
    fprintf(stderr,"Usage: ./recv_packet.o [port] [packet_size] [send_num]\n");
    return 1;
  }

  int port = atoi(argv[1]);
  int packet_size = atoi(argv[2]);
  int send_num = atoi(argv[3]);
  struct sockaddr_in src_addr_info;
  struct sockaddr_in addr;
  socklen_t addrlen;


  if(send_num < 0) {
    fprintf(stderr,"send_num must positive integer.\n");
    return 1;
  }

  int sock = socket(PF_INET, SOCK_DGRAM, 0);
  if(sock < 0){
    perror("socket() failed\n");
    return 1;
  }

  //portを固定する為にbindをする
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;
  bind(sock, (struct sockaddr *)&addr, sizeof(addr));


  char * buf = malloc(sizeof(char) * (packet_size + 1));

  fprintf(stderr, "start recieving packets...\n");
  fprintf(stderr, "packet size:%d\tsend_num:%d\n", packet_size, send_num);
  for(int i = 0; i < send_num; i++) {
    int result = recvfrom(sock, buf, packet_size, 0, (struct sockaddr *) &src_addr_info, &addrlen);
    if(result != packet_size) {
      fprintf(stderr,"%d-th try failed. (size res) = (%d %d)", i, packet_size, result);
    }
  }

  char sender_ipv4[16];
  inet_ntop(AF_INET, &src_addr_info.sin_addr, sender_ipv4, sizeof(sender_ipv4));
  printf("recvfrom: %s, port=%d\n", sender_ipv4, ntohs(src_addr_info.sin_port));
  fprintf(stderr, "recieved all packet.\n");
  return 0;
}
