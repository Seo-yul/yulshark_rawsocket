/*
 *      본 파일은 tcp.c의 udp 버전입니다. 사용 방법은 tcp와 동일합니다.
 *      
 *      해당 파일또한 udp프로토콜을 모두 수집하나, 실행시 dns를 인자로 입력하여 log_dns.txt파일을 출력합니다.
 *      
 *      https://github.com/seoyulsay/yulshark_rawsocket.git 에서 최신버전 다운이 가능합니다.
 *
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUFFER_SIZE 65536

FILE *logfile;
int sock_raw;
struct sockaddr_in source, dest;

void ProcessPacket(unsigned char *, int, char *);
void LogIpHeader(unsigned char *, int, char *);
void LogEthernetHeader(unsigned char *, int);
void LogUdpPacket(unsigned char *, int, char *);
void LogData(unsigned char *, int);

int main(int argc, char *argv[])
{
    char ip_source[18];
    char * pip_so = ip_source;
    char udp_port[7];
    char * pudp_po = udp_port;

    printf("+------ 캡 처 프 로 그 램 시 작 --------+\n");

    strcpy(pudp_po,argv[1]);
    printf("| 캡처하는 port: %s\n",pudp_po);

    strcpy(pip_so, argv[2]);
    printf("| 캡처하는   ip: %s\n",pip_so);

    printf("+--------------------------------------+\n");

    socklen_t saddr_size;
    int data_size;
    struct sockaddr saddr;
    struct in_addr in;

    unsigned char *buffer = (unsigned char *) malloc(BUFFER_SIZE);

    if(!strcmp(pudp_po,"dns")){
        logfile = fopen("log_dns.txt", "w");
        printf("log_dns.txt.로 기록을 시작합니다.");
        if (logfile == NULL) {
            printf("dns 로그파일 생성 실패.\n.");
            return 1;
        }
    }else{
        printf("에러야 에러.\n");
        return 1;
    }

    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        printf("소켓 초기화 실패.\n");
        return 1;
    }

    while (1) {
        saddr_size = sizeof saddr;

        data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, &saddr, &saddr_size);
        if (data_size < 0) {
            printf("데이터 사이즈 리턴값 0보다 작은 에러다.\n");
            return 1;
        }

        ProcessPacket(buffer, data_size, pip_so);
    }

    close(sock_raw);

    return 0;
}

void ProcessPacket(unsigned char *buffer, int size, char *pip_so)
{
    struct iphdr *iph = (struct iphdr*) (buffer + sizeof(struct ethhdr));

    switch (iph->protocol) {
        case 17: // UDP 프로토콜
            LogUdpPacket(buffer, size, pip_so);
            break;
        default: // 다른거
            printf("UDP 아니라서 지나갑니다.\n");
    }
}

void LogEthernetHeader(unsigned char *buffer, int size)
{
    struct ethhdr *eth = (struct ethhdr *) buffer;

    fprintf(logfile, "\n");
    fprintf(logfile, "Ethernet Header\n");
    fprintf(logfile, "Protocol        : %u \n",(unsigned short) eth->h_proto);
}

void LogIpHeader(unsigned char *buffer, int size, char *pip_so)
{
    LogEthernetHeader(buffer, size);

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *) (buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
    memset(&source, 0, sizeof(source));


    iph->saddr=inet_addr(pip_so);
    source.sin_addr.s_addr = iph->saddr;


    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(logfile, "\n");
    fprintf(logfile, "IP Header\n");
    fprintf(logfile, " | IP Version          : %d\n", (unsigned int) iph->version);
    fprintf(logfile, " | IP Header Length    : %d DWORDS or %d Bytes\n", (unsigned int) iph->ihl, ((unsigned int) (iph->ihl)) * 4);
    fprintf(logfile, " | Type Of Service     : %d\n", (unsigned int) iph->tos);
    fprintf(logfile, " | IP Total Length     : %d  Bytes (Size of Packet)\n", ntohs(iph->tot_len));
    fprintf(logfile, " | TTL                 : %d\n", (unsigned int) iph->ttl);
    fprintf(logfile, " | Protocol            : %d\n", (unsigned int) iph->protocol);
    fprintf(logfile, " | Checksum            : %d\n", ntohs(iph->check));
    fprintf(logfile, " | Source IP           : %s\n", inet_ntoa(source.sin_addr));
    fprintf(logfile, " | Destination IP      : %s\n", inet_ntoa(dest.sin_addr));
}
void LogUdpPacket(unsigned char *buffer, int size, char *pip_so){
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct udphdr *udph = (struct udphdr *) (buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    fprintf(logfile, "\n\n- - - - - - - - - - - - UDP Packet - - - - - - - - - - - - \n");

    LogIpHeader(buffer, size, pip_so);           

    fprintf(logfile, "\nUDP Header\n");
    fprintf(logfile, " |-Source Port      : %d\n", ntohs(udph->source));
    fprintf(logfile, " |-Destination Port : %d\n", ntohs(udph->dest));
    fprintf(logfile, " |-UDP Length       : %d\n", ntohs(udph->len));
    fprintf(logfile, " |-UDP Checksum     : %d\n", ntohs(udph->check));

    fprintf(logfile, "\n");
    fprintf(logfile, "IP Header\n");
    LogData(buffer, iphdrlen);

    fprintf(logfile, "UDP Header\n");
    LogData(buffer + iphdrlen, sizeof udph);

    fprintf(logfile, "Data Payload\n");
    //문자열 값만큼 줄이면서 포인터 진행
    LogData(buffer + header_size, size - header_size);

    fprintf(logfile, "\n- - - - - - - - - - - - - - - - - - - - - - - - ");


}

void LogData(unsigned char *buffer, int size)
{
    int i, j, a=0, b=16;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0) { // i가 16이면 한줄끝

            for (j = i - 16; j < i; j++) {
                if (buffer[j] >= 32 && buffer[j] <= 128) {
                    fprintf(logfile, " %c", (unsigned char) buffer[j]); // 문자하나씩 버퍼에서
                } else {
                    fprintf(logfile, "  "); // 없으면 공백찍는다
                }
            }
            fprintf(logfile,"\t\n");
        }

        if (i % 16 == 0) {
            fprintf(logfile, " ");
        }
        fprintf(logfile, " %02X", (unsigned int) buffer[i]);
         
        if (i == size - 1) { 
            for(j = 0; j < 15 - i % 16; j++)  {
                fprintf(logfile, "  "); //여백
            }

            for(j = i - i % 16; j <= i; j++) {
                if(buffer[j] >= 32 && buffer[j] <= 128) {
                    fprintf(logfile, " %c", (unsigned char) buffer[j]);
                } else {
                    fprintf(logfile, "  ");
                }
            }

            fprintf(logfile,  "\n");
        }
    }
}
