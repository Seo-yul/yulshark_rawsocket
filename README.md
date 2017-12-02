# yulshark_rawsocket
using raw socket, 패킷캡처 http,telnet,ftp,dns

해당 프로젝트는 한국산업기술대학교 네트워크프로그래밍 수업에서
raw socket을 이용하여 패킷을 캡처하는 실습을 하기위해서 만들어진것입니다.

+ - - - - 프로젝트 구성과 사용방법 - - - - +
c 파일            실행파일
tcp.c           shark_tcp
udp.c           shark_udp

+ - - - - 캡처 실행 방법 - - - - +

$ shark_tcp "프로토콜명" "ip 주소"
$ shark_upd "프로토콜명" "ip 주소"

+ - - - - 결과 생성파일 - - - - +

http   ->   log_http.txt
ftp    ->    log_ftp.txt
telnet -> log_telnet.txt
dns    ->    log_dns.txt

+ - - - - 작성자 - - - - +
seoyulsay
                02. 12. 2017
