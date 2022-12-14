# Cyber Lighthouse

[![golang](https://img.shields.io/badge/%3C%2F%3E-golang-blue)](https://github.com/golang/go)
[![cobra](https://img.shields.io/badge/Powered%20by-cobra-brightgreen)](https://github.com/spf13/cobra)
[![mongodb](https://img.shields.io/badge/Powered%20by-mongodb-brightgreen)](https://github.com/mongodb/mongo)

A simple DNS query client (likes command `dig` in linux) and server (local cache server) which support both UDP and TCP connections, including a light DNS message parser and generator.

## Feature

The project includes client and server, powered by a light DNS message parser and generator.

Both client and server support net connection through UDP and TCP, and the following DNS records.

```
A
NS
CNAME
AAAA
MX
```

The client can customize the DNS query server, and can also define whether to enable recursive query. 

The server can customize whether to enable recursive query and support concurrent query. It can also cache recent A record queries through database.

## Build

Download all dependencies.

```shell
$ cd src
$ go mod download
$ cd ../client
$ go mod download
$ cd ../server
$ go mod download
$ cd ..
```

Build client and server.

```shell
$ mkdir build
$ cd client
$ go build -o ../build/digg main.go
$ cd ../server
$ go build -o ../build/digd main.go
$ cd ..
```

The built file is generated into `build` folder.

All in one command

```shell
$ mkdir build; cd src; go mod download; cd ../client; go mod download; go build -o ../build/digg main.go; cd ../server; go mod download; go build -o ../build/digd main.go; cd ..
```

## Usage

### Server

After building, run the following command to start server.

```shell
$ cd build
$ ./digd
```

It will listening on `localhost:53`.

If you want to use database to cache A records, please install MongoDB first.

You can test the server by running the following command.

```shell
$ dig google.com @localhost
```

### Client

Likes `dig` command, there are some examples to use the client.

```shell
$ cd build
$ ./digg google.com
$ ./digg NS google.com --server=114.114.114.114 # Define DNS server by yourself
$ ./digg A google.com --server=192.5.6.30 --recursion=false # Do query without recursion
$ ./digg -h # Output help list
```

## Testing

Unit tests cover `Parser` and `Generator` only.

```shell
$ cd src
$ go test CyberLighthouse/packet -v
```

`Generator` is using `Parser` to check the validation of data.

## LICENSE

GNU General Public License v3.0

-----

## Project Logs

????????????????????????????????????????????????????????????????????? `push`??????

| ?????? | ?????? | ???????????? | ???????????? |
| :---: | :--- | :---: | :---: |
| ?????? 1 | ????????? | ??? | Day 1 |
| ?????? 2 | DNS ??????????????? | ??? | Day 4 |
| ?????? 2 | ????????????????????? ?????? AAAA MX | ??? | Day 4 |
| ?????? 2 | DNS ??????????????? | ??? | Day 5 |
| ?????? 2 | ????????????????????? ?????? AAAA MX | ??? | Day 5 |
| ?????? 3 | DNS Client | ??? | Day 5 |
| ?????? 3 | DNS Client?????????????????? AAAA MX | ??? | Day 5 |
| ?????? 3 | DNS Client?????????????????? TCP | ??? | Day 7 |
| ?????? 4 | DNS Server ???????????? | ??? | Day 6 |
| ?????? 4 | DNS Server ?????? | ??? | Day 6 |
| ?????? 4 | DNS Server?????????????????? AAAA MX | ??? | Day 6 |
| ?????? 4 | DNS Server??????????????????????????? | ??? | Day 6 |
| ?????? 4 | DNS Server???????????????????????????????????? | ??? | Day 6 |
| ?????? 4 | DNS Server?????????????????? TCP | ??? | Day 7 |
| ?????? 4 | DNS Server?????????????????????????????? | ??? | Day 7 |
| ?????? 4 | DNS Server???????????????????????? | ??? | Day 6 |

### Task 1

??????????????????????????????????????????????????????????????????????????????

- ?????????????????????????????? <https://www.ruanyifeng.com/blog/2012/05/internet_protocol_suite_part_i.html>
- ?????????????????????????????? <https://www.ruanyifeng.com/blog/2012/06/internet_protocol_suite_part_ii.html>
- DNS ???????????? <https://www.ruanyifeng.com/blog/2016/06/dns.html>
- DNS ?????????????????? <https://www.ruanyifeng.com/blog/2022/08/dns-query.html>
- DNS?????????????????? <http://c.biancheng.net/view/6457.html>
- google/gopacket <https://github.com/google/gopacket>
- DNS????????????:?????? VS ?????? <https://www.jianshu.com/p/6b502d0f2ede>

??????????????????????????????????????? RFC 1035

- RFC1035 DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION <https://www.rfc-editor.org/rfc/rfc1035>

?????????????????????????????? DNS ?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????

???????????????????????????????????????????????????????????????

??????????????????????????????????????????????????????????????? DNS ??????????????????????????????????????????????????????????????????????????? UDP ?????????

?????????????????????????????????????????????????????????????????????????????????????????? DNS ?????????????????????????????????????????????????????????????????? A ?????????

Let's go!

### Task 2

Wireshark ??????

???????????????

```
Domain Name System (query)
    Transaction ID: 0x8bca
    Flags: 0x0120 Standard query
        0... .... .... .... = Response: Message is a query
        .000 0... .... .... = Opcode: Standard query (0)
        .... ..0. .... .... = Truncated: Message is not truncated
        .... ...1 .... .... = Recursion desired: Do query recursively
        .... .... .0.. .... = Z: reserved (0)
        .... .... ..1. .... = AD bit: Set
        .... .... ...0 .... = Non-authenticated data: Unacceptable
    Questions: 1
    Answer RRs: 0
    Authority RRs: 0
    Additional RRs: 1
    Queries
        google.com: type A, class IN
            Name: google.com
            [Name Length: 10]
            [Label Count: 2]
            Type: A (Host Address) (1)
            Class: IN (0x0001)
    Additional records
        <Root>: type OPT
            Name: <Root>
            Type: OPT (41)
            UDP payload size: 4096
            Higher bits in extended RCODE: 0x00
            EDNS0 version: 0
            Z: 0x0000
                0... .... .... .... = DO bit: Cannot handle DNSSEC security RRs
                .000 0000 0000 0000 = Reserved: 0x0000
            Data length: 12
            Option: COOKIE
```

???????????????

```
Domain Name System (response)
    Transaction ID: 0x8bca
    Flags: 0x8180 Standard query response, No error
        1... .... .... .... = Response: Message is a response
        .000 0... .... .... = Opcode: Standard query (0)
        .... .0.. .... .... = Authoritative: Server is not an authority for domain
        .... ..0. .... .... = Truncated: Message is not truncated
        .... ...1 .... .... = Recursion desired: Do query recursively
        .... .... 1... .... = Recursion available: Server can do recursive queries
        .... .... .0.. .... = Z: reserved (0)
        .... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server
        .... .... ...0 .... = Non-authenticated data: Unacceptable
        .... .... .... 0000 = Reply code: No error (0)
    Questions: 1
    Answer RRs: 1
    Authority RRs: 0
    Additional RRs: 1
    Queries
        google.com: type A, class IN
            Name: google.com
            [Name Length: 10]
            [Label Count: 2]
            Type: A (Host Address) (1)
            Class: IN (0x0001)
    Answers
        google.com: type A, class IN, addr 31.13.85.169
            Name: google.com
            Type: A (Host Address) (1)
            Class: IN (0x0001)
            Time to live: 702 (11 minutes, 42 seconds)
            Data length: 4
            Address: 31.13.85.169
    Additional records
        <Root>: type OPT
            Name: <Root>
            Type: OPT (41)
            UDP payload size: 4096
            Higher bits in extended RCODE: 0x00
            EDNS0 version: 0
            Z: 0x0000
                0... .... .... .... = DO bit: Cannot handle DNSSEC security RRs
                .000 0000 0000 0000 = Reserved: 0x0000
            Data length: 28
            Option: COOKIE
```

Day 1 ????????? `struct` ??????????????????????????????????????????[??????](https://www.rfc-editor.org/rfc/rfc1035.html)???????????????????????????????????????????????????????????????????????????

`Additional Records` ?????????????????????????????????????????????

??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????

```shell
$ dig google.com @localhost
```

Day 2 ?????????????????????????????????????????????

Day 3 ???????????????????????????

Day 4

?????? `Additional Records` ??????????????? `type OPT` ???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? `type OPT` ???????????????????????????????????????????????????????????????? cookie ????????????????????????

????????? `Parser` ?????????????????????????????????????????????

`dig query` ???????????????

```
Domain Name System (query)
        Transaction ID: 0xa6
        Flags:
                Response: Message is a query
                Opcode: Standard query (0)
                Truncated: Message is not truncated
                Recursion desired: Do query recursively
                Z: reserved (0)
                AD bit: Set
                Non-authenticated data: Unacceptable
        Questions: 1
        Answer RRs: 0
        Authority RRs: 0
        Additional RRs: 1
        Queries:
                [0] queries
                        Name: google.com.
                        Type: A (1)
                        Class: IN (0x0001)
        Additional records:
                [0] additional records
                        Name: <Root>
                        Type: Not supported record (41)
                        Class: Not supported class (0x1000)
                        Time to live: 0
                        Data length: 12
                        Not supported record. data = [0 10 0 8 88 27 51 97 69 16 159 161]
```

????????????????????????????????? bug???

```shell
$ go test CyberLighthouse/packet -v
```

Day 5

`Generator` ?????????????????????????????????????????????

`dig query` ???????????????

```
[55 140 1 32 0 1 0 0 0 0 0 1 6 103 111 111 103 108 101 3 99 111 109 0 0 16 0 1 0 0 41 16 0 0 0 0 0 0 12 0 10 0 8 112 159 32 187 233 116 227 147]
```

?????????????????????

????????????????????????????????? bug???

??????????????????????????????

### Task 3

?????????[golang???????????????cli?????????/????????????????????????-cobra??????](https://www.cnblogs.com/jiujuan/p/15487918.html)

spf13/cobra: <https://github.com/spf13/cobra>

??????????????????????????????????????????????????????????????? `cobra` ???????????????????????????

?????? UDP ???????????????????????????????????????

`Client` ???????????????????????????????????????????????????????????? `8.8.8.8` ???????????????????????????????????????????????????????????????

??????????????????????????????????????? `dig google.com @8.8.8.8` ??????????????????????????????????????????????????????

????????????????????????????????? `Header Flag RD` ????????????????????????????????????????????????

??????????????????

```shell
$ cd client
$ go build -o digg main.go
$ ./digg
$ ./digg -h
$ ./digg google.com
$ ./digg A google.com --recursion=false --server=202.114.0.131
$ ./digg MX google.com --server=202.114.0.131
$ ./digg NS google.com --server=202.114.0.131
$ ./digg CNAME mc.ligen131.com
$ ./digg AAAA ns1.google.com
$ ./digg NS .
```

????????????

```shell
$ ./digg MX google.com --server=202.114.0.131
Receive data from 202.114.0.131:53, UDP package length = 49
The query result:
---------------------------------
Domain Name System (response)
        Transaction ID: 0x17c0
        Flags:
                Response: Message is a response
                Opcode: Standard query (0)
                Authoritative: Server is not an authority for domain
                Truncated: Message is not truncated
                Recursion desired: Do query recursively
                Recursion available: Server can do recursive queries
                Z: reserved (0)
                Answer authenticated: Answer/authority portion was not authenticated by the server
                Non-authenticated data: Unacceptable
                Reply code: No error (0)
        Questions: 1
        Answer RRs: 1
        Authority RRs: 0
        Additional RRs: 0
        Queries:
                [0] queries
                        Name: google.com
                        Type: MX (15)
                        Class: IN (0x0001)
        Answers:
                [0] answers
                        Name: google.com
                        Type: MX (15)
                        Class: IN (0x0001)
                        Time to live: 3600
                        Data length: 9
                        Mail Exchange: Preference: 10; Name: smtp.google.com
---------------------------------
```

???????????????????????????TCP ????????????????????? GO ??? TCP ????????? OK???????????????????????????

### Task 4

> ???????????? Cyber Lighthouse ??????

Day 6

??????????????? Day 6 ??????

?????? `Server` ???????????????????????????????????????????????????

??????????????? `dig` ???????????????????????????????????? `dig aaaa google.com`??????

???????????????

```shell
$ cd server
$ go build -o digd main.go
$ ./digd # ?????????????????????????????????
$ ./digd --recursion=false # ???????????????????????????
```

?????? `dig` ??????

```shell
$ dig google.com @localhost
$ dig mx google.com @localhost
$ dig aaaa ns1.google.com @localhost
$ dig ns google.com @localhost
$ dig cname mc.ligen131.com @localhost
$ dig txt google.com @localhost # ??????????????????????????????????????????????????????
```

????????????

?????????????????????

```shell
$ dig google.com @localhost
# ???????????????
Listening on 127.0.0.1:53...
[Server] Read package from 127.0.0.1:62103, length = 51
[Client] Receive UDP package from 192.5.6.30:53, length = 54
# dig ??????
; <<>> DiG 9.16.1-Ubuntu <<>> google.com @localhost
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 44151
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;google.com.                    IN      A

;; ANSWER SECTION:
google.com.             60      IN      A       46.82.174.69

;; Query time: 39 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Thu Oct 06 02:22:22 CST 2022
;; MSG SIZE  rcvd: 54
```

?????????????????????

```shell
$ dig ligen131.com @localhost
# ???????????????
Listening on 127.0.0.1:53...
[Server] Read package from 127.0.0.1:56638, length = 53
[Client] Receive UDP package from 192.5.6.30:53, length = 78
[Client] Receive UDP package from 192.33.14.30:53, length = 78
[Client] Receive UDP package from 192.26.92.30:53, length = 78
[Client] Receive UDP package from 192.31.80.30:53, length = 78
[Client] Receive UDP package from 192.12.94.30:53, length = 78
[Client] Receive UDP package from 192.35.51.30:53, length = 78
[Client] Receive UDP package from 192.42.93.30:53, length = 78
[Client] Receive UDP package from 192.54.112.30:53, length = 78
[Client] Receive UDP package from 192.43.172.30:53, length = 78
[Client] Receive UDP package from 192.48.79.30:53, length = 78
[Client] Receive UDP package from 192.52.178.30:53, length = 78
[Client] Receive UDP package from 192.41.162.30:53, length = 78
[Client] Receive UDP package from 192.55.83.30:53, length = 78
# dig ??????
; <<>> DiG 9.16.1-Ubuntu <<>> ligen131.com @localhost
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 8893
;; flags: qr rd ad; QUERY: 1, ANSWER: 0, AUTHORITY: 2, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;ligen131.com.                  IN      A

;; AUTHORITY SECTION:
ligen131.com.           172800  IN      NS      buck.dnspod.net.
ligen131.com.           172800  IN      NS      duet.dnspod.net.

;; Query time: 2536 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Thu Oct 06 02:24:05 CST 2022
;; MSG SIZE  rcvd: 112
```

??????????????????????????? `NS` ?????? `A` ???

???????????????????????????????????????????????????

??????????????????????????? `ExecuteFunction()` ??????????????? `go` ????????????????????????????????????????????????????????????????????????????

?????? `dig aaaa google.com @localhost` ????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????

?????????????????????????????? `Client` ???????????? I/O ????????????????????????????????????????????????????????????????????????????????????????????????

?????? `dig aaaa google.com` ??????????????????????????????

????????????????????????????????????????????????????????????MongoDB?????????????????????????????????????????????????????????????????????????????????????????????????????????

????????????

```shell
$ dig ligen131.com @localhost
$ dig ligen131.com @localhost
$ dig ligen131.com @localhost
# ???????????????
Listening on 127.0.0.1:53...
[Server] Read package from 127.0.0.1:61079, length = 53
[Client] Receive UDP package from 192.5.6.30:53, length = 78
[Client] Receive UDP package from 192.5.6.30:53, length = 208
[Client] Receive UDP package from 1.12.0.29:53, length = 108
[Client] Receive UDP package from 117.89.178.226:53, length = 104
[Server] Read package from 127.0.0.1:61086, length = 53
[Server] Read package from 127.0.0.1:61089, length = 53
```

??????????????? `map` ??????????????????

????????????????????????????????????????????????

?????????????????? `AAAA MX` ???????????????????????????????????????

?????????????????? `push` ????????????????????????????????? bug ???

```shell
$ dig buck.dnspod.net @localhost
$ dig ligen131.com @localhost
$ dig ligen131.com @localhost
$ dig github.com @localhost
$ dig github.com @localhost
# ???????????????
Listening on 127.0.0.1:53...
[Server] Read package from 127.0.0.1:53074, length = 56
[Client] Receive UDP package from 192.5.6.30:53, length = 208
[Client] Receive UDP package from 1.12.0.29:53, length = 167
[Server] Read package from 127.0.0.1:55774, length = 53
[Client] Receive UDP package from 192.5.6.30:53, length = 78
Read cache buck.dnspod.net., len = 5
[112 80 181 45]
[120 241 130 98]
[129 211 176 187]
[1 12 0 4]
[61 151 180 44]
[Client] Receive UDP package from 112.80.181.45:53, length = 104
[Server] Read package from 127.0.0.1:64660, length = 53
Read cache ligen131.com., len = 1
[1 12 241 26]
[Server] Read package from 127.0.0.1:58341, length = 51
[Client] Receive UDP package from 192.5.6.30:53, length = 267
[Client] Receive UDP package from 205.251.193.165:53, length = 267
[Server] Read package from 127.0.0.1:58346, length = 51
Read cache github.com., len = 1
[20 205 243 166]
```

??????????????????

```shell
$ ./digg baidu.com --server=127.0.0.1
$ ./digg baidu.com --server=127.0.0.1
# ???????????????
[Server] Read package from 127.0.0.1:54384, length = 27
[Client] Receive UDP package from 192.5.6.30:53, length = 285
[Client] Receive UDP package from 220.181.33.31:53, length = 317
[Server] Read package from 127.0.0.1:54387, length = 27
Read cache baidu.com., len = 2
[39 156 66 10]
[110 242 68 66]
```

Timeout ??????????????????????????????

MongoDB ?????????Go????????????mongoDB <https://www.liwenzhou.com/posts/Go/go_mongodb/>

?????????????????????????????????????????????????????????????????????????????????

????????????

```shell
$ dig qq.com @localhost
$ dig qq.com @localhost
$ dig qq.com @localhost # ??????????????????
# ???????????????
Listening on 127.0.0.1:53...
[Server] Read package from 127.0.0.1:51307, length = 47
[MongoDB] Clean 4 expired records.
[Cache] Error while query records in the database. error info = MongoDB didn't find anything about qq.com.
[Client] Receive UDP package from 192.5.6.30:53, length = 392
[MongoDB] Clean 0 expired records.
[Cache] Error while query records in the database. error info = MongoDB didn't find anything about qq.com.
[Client] Receive UDP package from 101.89.19.165:53, length = 160
[Server] Read package from 127.0.0.1:51312, length = 47
[MongoDB] Clean 0 expired records.
Read cache qq.com., len = 4
[183 3 226 35]
[203 205 254 157]
[123 151 137 18]
[61 129 7 47]
# ??????????????????
Listening on 127.0.0.1:53...
[Server] Read package from 127.0.0.1:55475, length = 47
[MongoDB] Clean 3 expired records.
Read cache qq.com., len = 4
[183 3 226 35]
[203 205 254 157]
[123 151 137 18]
[61 129 7 47]
```

Day 7

????????????????????????????????????????????????

???????????????????????????????????? TCP ???????????????????????? `dig +vc google.com` ?????? TCP ??????????????????????????? `Data Length` ?????????

??? `Client` ????????? TCP ????????????????????? `Server` ?????????????????????????????????????????? TCP ??????

????????????????????????????????????????????????????????????????????????????????????????????????

????????? `Client` ???????????????????????? `8.8.8.8` ?????????????????????????????????????????????????????????????????????????????????????????????????????? `8.8.8.8` ????????????????????????????????????????????????????????????????????????? 3s?????????????????????????????????????????? 200ms ?????????

?????????????????????

TCP Test

```shell
$ ./digg --tcp google.com
```

?????????Go ?????? socket ???????????? <https://luyuhuang.tech/2021/01/24/reuse-port.html>

???????????????????????????????????????gogf/greuse <https://github.com/gogf/greuse>

??? `Server` ?????? TCP ?????????

?????? `dig` ??????

```shell
$ dig google.com @localhost +vc
$ dig mx google.com @localhost +vc
$ dig aaaa ns1.google.com @localhost +vc
$ dig ns google.com @localhost +vc
$ dig cname mc.ligen131.com @localhost +vc
$ dig txt google.com @localhost +vc # ??????????????????????????????????????????????????????
```

??????????????????????????????

```shell
$ ./digd --tcp=true --udp=true
```

ALL MISSIONS COMPLETED!

???????????????????????????

```shell
$ ./digg ns google.com --tcp --server=127.0.0.1
[Client] Receive TCP package from [127.0.0.1]:53, length = 182
The query result:
---------------------------------
;; Reply code: No error (0)
;; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTIONS SECTION:
google.com.     IN      NS

;; ANSWERS SECTION:
google.com.     IN      NS      172800  ns2.google.com.
google.com.     IN      NS      172800  ns1.google.com.
google.com.     IN      NS      172800  ns3.google.com.
google.com.     IN      NS      172800  ns4.google.com.
---------------------------------
```

?????????????????? `PacketParser` ????????? `Packet` ???
