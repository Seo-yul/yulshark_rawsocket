/*
 * 해당파일은 raw socket을 이용하여 tcp 패킷을 캡처하는 코드입니다.
 * 실행방법은 첫번째 파라매터값으로 http, ftp, telnet 중 하나를 입력하고
 *            두번째 파라매터값으로 source ip를 입력하면 됩니다.
 * 파일의 손상, 수정으로 인해 재 다운을 원하거나 오류가 수정된 최신 코드는
 *
 * https://github.com/seoyulsay/yulshark_rawsocket.git 에서 다운받으실수 있습니다.
 *
 * 해당 코드는 사용 프로토콜을 파라미터로 받으나 캡처를 각각 하는게 아닌 log 파일만을 다르게 생성해줍니다.
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
void LogTcpPacket(unsigned char *, int, char *);
void LogData(unsigned char *, int);

int main(int argc, char *argv[])
{
    char ip_source[18];
    char * pip_so = ip_source;
    char tcp_port[7];
    char * ptcp_po = tcp_port;

    printf("+------ 캡처 프로그램 시작-------+\n");

    strcpy(ptcp_po,argv[1]);
    printf("| 캡처하는 port:   %s\n",&ptcp_po);

    strcpy(pip_so,argv[2]);
    printf("| 캡처하는   ip:   %s\n",&pip_so);

    printf("+--------------------------------+\n");

    socklen_t saddr_size;
    int data_size;
    struct sockaddr saddr;
    struct in_addr in;

    unsigned char *buffer = (unsigned char *) malloc(BUFFER_SIZE);
    
    if(!strcmp(ptcp_po,"http")){
            logfile = fopen("log_http.txt", "w");
            printf("log_http.txt로 기록을 시작합니다..");
            if (logfile == NULL) {
                printf("http 로그파일 생성 실패.\n");
                return 1;
            }
    }else if(!strcmp(ptcp_po,"ftp")){
        logfile = fopen("log_ftp.txt", "w");
        printf("log_ftp.txt로 기록을 시작합니다..");
        if (logfile == NULL){
            printf("ftp 로그파일 생성 실패.\n");
            return 1;
            }
    }else if(!strcmp(ptcp_po,"telnet")){
        logfile = fopen("log_telnet.txt", "w");
        printf("log_telnet.txt로 기록을 시작합니다..");
        if (logfile == NULL){
            printf("telnet 로그파일 생성 실패.\n");
            return 1;
            }
    }else{
        printf("이게보이면 큰일난거다. 모르는 에러다. \n");
        return 1;
    }
    //AF_INET, SOCK_PACKET으로하면 Layer2 까지 조작 밑에껀 Layer3까지 조작
    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        printf("소켓  초기화 실패\n");
        return 1;
    }

    while (1) {
        saddr_size = sizeof saddr;

        data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, &saddr, &saddr_size);
        if (data_size < 0) {
            printf("리턴값0보다 작은 에러");
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
        case 6: // TCP 프로토콜
            LogTcpPacket(buffer, size, pip_so);
            break;
        default:
            printf("TCP가 아니라 지나가요.\n");
    }
}

void LogEthernetHeader(unsigned char *buffer, int size)
{
    struct ethhdr *eth = (struct ethhdr *) buffer;

    fprintf(logfile, "\n");
    fprintf(logfile, "Ethernet Header\n");
    fprintf(logfile, "Protocol            : %u \n",(unsigned short) eth->h_proto);
}

void LogIpHeader(unsigned char *buffer, int size, char * pip_so)
{
    LogEthernetHeader(buffer, size);

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *) (buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    memset(&source, 0, sizeof(source));
    
    iph->saddr=inet_addr(pip_so); 
    source.sin_addr.s_addr = iph->saddr;//여기다 ip정해서 테스트
    
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(logfile, "\n");
    fprintf(logfile, "IP Header\n");
    fprintf(logfile, " + IP Version          : %d\n", (unsigned int) iph->version);
    fprintf(logfile, " | P Header Length    : %d DWORDS or %d Bytes\n", (unsigned int) iph->ihl, ((unsigned int) (iph->ihl)) * 4);
    fprintf(logfile, " | Type Of Service     : %d\n", (unsigned int) iph->tos);
    fprintf(logfile, " | IP Total Length     : %d  Bytes (Size of Packet)\n", ntohs(iph->tot_len));
    fprintf(logfile, " | TTL                 : %d\n", (unsigned int) iph->ttl);
    fprintf(logfile, " | Protocol            : %d\n", (unsigned int) iph->protocol);
    fprintf(logfile, " | Checksum            : %d\n", ntohs(iph->check));
    fprintf(logfile, " | Source IP           : %s\n", inet_ntoa(source.sin_addr));
    fprintf(logfile, " + Destination IP      : %s\n", inet_ntoa(dest.sin_addr));
}

void LogTcpPacket(unsigned char *buffer, int size, char *pip_so)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct tcphdr *tcph = (struct tcphdr *) (buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff * 4;
    if((22!=ntohs(tcph->source))&&(22!=ntohs(tcph->dest))){
        fprintf(logfile, "\n\n- - - - - - - - - - - TCP Packet - - - - - - - - - - - - \n");  

        LogIpHeader(buffer, size, pip_so);

        fprintf(logfile, "\n");
        fprintf(logfile, "TCP Header\n");
        fprintf(logfile, " + Source Port          : %u\n", ntohs(tcph->source));
        fprintf(logfile, " | Destination Port     : %u\n", ntohs(tcph->dest));
        fprintf(logfile, " | Sequence Number      : %u\n", ntohl(tcph->seq));
        fprintf(logfile, " | Acknowledge Number   : %u\n", ntohl(tcph->ack_seq));
        fprintf(logfile, " | Header Length        : %d DWORDS or %d BYTES\n", (unsigned int) tcph->doff, (unsigned int) tcph->doff * 4);
        fprintf(logfile, " | Urgent Flag          : %d\n", (unsigned int) tcph->urg);
        fprintf(logfile, " | Acknowledgement Flag : %d\n", (unsigned int) tcph->ack);
        fprintf(logfile, " | Push Flag            : %d\n", (unsigned int) tcph->psh);
        fprintf(logfile, " | Reset Flag           : %d\n", (unsigned int) tcph->rst);
        fprintf(logfile, " | Synchronise Flag     : %d\n", (unsigned int) tcph->syn);
        fprintf(logfile, " | Finish Flag          : %d\n", (unsigned int) tcph->fin);
        fprintf(logfile, " | Window               : %d\n", ntohs(tcph->window));
        fprintf(logfile, " | Checksum             : %d\n", ntohs(tcph->check));
        fprintf(logfile, " + Urgent Pointer       : %d\n", tcph->urg_ptr);
        fprintf(logfile, "\n");
        fprintf(logfile, "                        DATA Dump                         ");

        fprintf(logfile, "\n");

        fprintf(logfile, "\nIP Header\n");
        LogData(buffer, iphdrlen);

        fprintf(logfile, "\nTCP Header\n");
        LogData(buffer + iphdrlen, tcph->doff * 4);

        fprintf(logfile, "\nData Payload\n");    
        LogData(buffer + header_size, size - header_size);

        fprintf(logfile, "\n- - - - - - - - - - - - - - - - - - - - - -");
    }
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
            fprintf(logfile, "");
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
