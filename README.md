# yulshark_rawsocket
using raw socket, http,telnet,ftp,dns,패킷캡처

해당 프로젝트는 한국산업기술대학교 네트워크프로그래밍 수업에서 </br> raw socket을 이용하여 패킷을 캡처하는 실습을 하기위해서 만들어진것입니다.
***
<b>1. 프로젝트 구성과 사용방법</b>
<pre> 
c 파일             실행파일
yulshark.c         shark

</pre>
<b>2. 캡처 실행 방법</b>
<pre> 
$ shark "프로토콜명" "ip 주소"

</pre>
<b>3. 결과 생성파일</b>
<pre> 
http   ->   log_http.txt
ftp    ->    log_ftp.txt
telnet -> log_telnet.txt
dns    ->    log_dns.txt
</pre>
<b>4. 결과 예시</b>
<pre>
<b>http</b>
<div>
<img src="https://user-images.githubusercontent.com/19742930/44986231-fa6e1c00-afbd-11e8-8d12-aed8baa492b6.png">
<img src="https://user-images.githubusercontent.com/19742930/44986233-fb9f4900-afbd-11e8-9236-02d69ef2ba74.png">
</div>
</pre>
<b>5. 작성자</b>
<pre> 
Yoon SeoYul
                01. 11. 2018
</pre>
***
