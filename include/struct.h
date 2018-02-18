/* structures.h - some used structures */

#include <netinet/ip.h>
#include <netinet/tcp.h>

struct ippacket {
    struct ip ip;
    struct tcphdr tcp;
    char something[12];
    char data[1024];
};

