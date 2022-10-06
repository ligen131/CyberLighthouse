# Cyber Lighthouse

[![golang](https://img.shields.io/badge/%3C%2F%3E-golang-blue)](https://github.com/golang/go)
[![cobra](https://img.shields.io/badge/Powered%20by-cobra-brightgreen)](https://github.com/spf13/cobra)

A simple DNS query client (likes command `dig` in linux) and server (local cache server), including a light DNS message parser and generator.

## Feature

The project includes client and server, powered by a light DNS message parser and generator.

Both client and server support net connection through UDP, and the following DNS records.

```
A
NS
CNAME
AAAA
MX
```

The client can customize the DNS query server, and can also define whether to enable recursive query. 

The server can customize whether to enable recursive query and support concurrent query. It can also cache recent A record queries.

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

每天的日志可能会不定时更新（指凌晨不知道几点才 `push`）。

| 阶段 | 任务 | 是否完成 | 完成时间 |
| :---: | :--- | :---: | :---: |
| 阶段 1 | 查资料 | ✅ | Day 1 |
| 阶段 2 | DNS 报文解析器 | ✅ | Day 4 |
| 阶段 2 | 解析器【进阶】 支持 AAAA MX | ✅ | Day 4 |
| 阶段 2 | DNS 报文生成器 | ✅ | Day 5 |
| 阶段 2 | 生成器【进阶】 支持 AAAA MX | ✅ | Day 5 |
| 阶段 3 | DNS Client | ✅ | Day 5 |
| 阶段 3 | DNS Client【进阶】支持 AAAA MX | ✅ | Day 5 |
| 阶段 3 | DNS Client【进阶】支持 TCP | ❌ | -- |
| 阶段 4 | DNS Server 递归查询 | ✅ | Day 6 |
| 阶段 4 | DNS Server 缓存 | ✅ | Day 6 |
| 阶段 4 | DNS Server【进阶】支持 AAAA MX | ✅ | Day 6 |
| 阶段 4 | DNS Server【进阶】缓存改存储 | ❌ | -- |
| 阶段 4 | DNS Server【进阶】支持递归查询开关 | ✅ | Day 6 |
| 阶段 4 | DNS Server【进阶】支持 TCP | ❌ | -- |
| 阶段 4 | DNS Server【进阶】支持协议更换 | ❌ | -- |
| 阶段 4 | DNS Server【进阶】支持并发 | ✅ | Day 6 |

### Task 1

找了大量的资料，算是基本弄懂了四个阶段分别要干什么。

- 互联网协议入门（一） <https://www.ruanyifeng.com/blog/2012/05/internet_protocol_suite_part_i.html>
- 互联网协议入门（二） <https://www.ruanyifeng.com/blog/2012/06/internet_protocol_suite_part_ii.html>
- DNS 原理入门 <https://www.ruanyifeng.com/blog/2016/06/dns.html>
- DNS 查询原理详解 <https://www.ruanyifeng.com/blog/2022/08/dns-query.html>
- DNS报文格式解析 <http://c.biancheng.net/view/6457.html>
- google/gopacket <https://github.com/google/gopacket>
- DNS解析原理:递归 VS 迭代 <https://www.jianshu.com/p/6b502d0f2ede>

最重要的是官方文档，总纲领 RFC 1035

- RFC1035 DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION <https://www.rfc-editor.org/rfc/rfc1035>

阶段二实现一个基本的 DNS 报文解析器和生成器，基本的想法是根据包格式的文档直接解包。这一步为后面的客户端和服务端做铺垫。

理解了好久客户端和服务端要做的事情的区别。

阶段三实现客户端，其实只需要发送一条报文给 DNS 服务器然后等待回应即可。命令行参数需要解析，发包用 UDP 协议。

阶段四实现缓存服务器，如果支持递归查询需要发送多条报文给多个 DNS 服务器进行查询，可能涉及包合并的问题，并缓存 A 记录。

Let's go!

### Task 2

Wireshark 抓包

询问包格式

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

回答包格式

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

Day 1 把包的 `struct` 写好了，但还没正式开始解析，[文档](https://www.rfc-editor.org/rfc/rfc1035.html)看了半天弄懂了一些细节上的问题，感觉细节是真的多。

`Additional Records` 和其他的记录格式还不一样。。。

运行以下指令可以把询问包扔到端口上。但是把回答包传到端口上，可能要手动实现了🤔

```shell
$ dig google.com @localhost
```

Day 2 要出去玩，可能没什么时间写了。

Day 3 怎么有人玩了两天。

Day 4

发现 `Additional Records` 只有最后的 `type OPT` 和其他的解析不同，但是偏移量仍然对得上，所以先按原来这样解析即可。（回看了下任务书，发现 `type OPT` 这玩意原来根本就不用管🤔，还研究了半天那个 cookie 是啥玩意。。。）

想不到 `Parser` 会写这么长。。。写了七八个小时

`dig query` 解析输出：

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

添加单元测试，修复一些 bug。

```shell
$ go test CyberLighthouse/packet -v
```

Day 5

`Generator` 还挺好写的，依葫芦画瓢就是了。

`dig query` 反解析结果

```
[55 140 1 32 0 1 0 0 0 0 0 1 6 103 111 111 103 108 101 3 99 111 109 0 0 16 0 1 0 0 41 16 0 0 0 0 0 0 12 0 10 0 8 112 159 32 187 233 116 227 147]
```

与原数据一致。

添加单元测试。修复一些 bug。

至此阶段二基本完成。

### Task 3

参考：[golang常用库包：cli命令行/应用程序生成工具-cobra使用](https://www.cnblogs.com/jiujuan/p/15487918.html)

spf13/cobra: <https://github.com/spf13/cobra>

既然任务书说了可以用命令行支持库，那直接用 `cobra` ，就不手动解析了。

收发 UDP 包其实在上一阶段就用到了。

`Client` 其实也不难实现，测试的时候发现发一个包到 `8.8.8.8` 会接收到两个包，但是默认只能解析第一个包。

这好像没法解决，然后试了下 `dig google.com @8.8.8.8` ，发现他也只解析第一个包。那不管了。

递归查询好像就是把包的 `Header Flag RD` 修改了一下，但好像没有什么效果。

构建后测试：

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

输出示例

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

第三阶段基本完成。TCP 也许是直接调用 GO 的 TCP 接口就 OK？后面再研究研究。

### Task 4

> 就快完成 Cyber Lighthouse 啦！

Day 6

凌晨了，算 Day 6 吧。

写完 `Server` 发现表里面四个任务全都可以打勾了。

有一些记录 `dig` 也查不了，就不管了（比如 `dig aaaa google.com`）。

服务端启动

```shell
$ cd server
$ go build -o digd main.go
$ ./digd # 默认开启可递归查询模式
$ ./digd --recursion=false # 关闭可递归查询模式
```

使用 `dig` 测试

```shell
$ dig google.com @localhost
$ dig mx google.com @localhost
$ dig aaaa ns1.google.com @localhost
$ dig ns google.com @localhost
$ dig cname mc.ligen131.com @localhost
$ dig txt google.com @localhost # 惊讶地发现这玩意还能查其他的记录嘿嘿
```

输出示例

开启递归模式：

```shell
$ dig google.com @localhost
# 服务端输出
Listening on 127.0.0.1:53...
[Server] Read package from 127.0.0.1:62103, length = 51
[Client] Receive UDP package from 192.5.6.30:53, length = 54
# dig 输出
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

关闭递归模式：

```shell
$ dig ligen131.com @localhost
# 服务端输出
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
# dig 输出
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

关闭递归模式后返回 `NS` 而非 `A` 。

从服务端输出记录可以看出递归查询。

至于并发，就只是在 `ExecuteFunction()` 前面加了个 `go` 开启多线程，如果这也算进阶？🤔还是对题目理解有误？

因为 `dig aaaa google.com @localhost` 会递归很久才返回结果，所以没有并发的结果是执行一条该命令就会卡住不动，开启并发后会对每条命令各开一个线程查询，实现并发。

解决上述卡住问题：在 `Client` 处设置了 I/O 超时时间。现在即使不开启并发也不会卡住了（可能是谷歌被墙问题）。

即使 `dig aaaa google.com` 也不会返回正确结果。

至于后面缓存改存储，初步想法是用数据库（MongoDB）解决，而数据库读写不需要考虑并发锁啥的（文件才要），所以应该也好写。

添加缓存

```shell
$ dig ligen131.com @localhost
$ dig ligen131.com @localhost
$ dig ligen131.com @localhost
# 服务端输出
Listening on 127.0.0.1:53...
[Server] Read package from 127.0.0.1:61079, length = 53
[Client] Receive UDP package from 192.5.6.30:53, length = 78
[Client] Receive UDP package from 192.5.6.30:53, length = 208
[Client] Receive UDP package from 1.12.0.29:53, length = 108
[Client] Receive UDP package from 117.89.178.226:53, length = 104
[Server] Read package from 127.0.0.1:61086, length = 53
[Server] Read package from 127.0.0.1:61089, length = 53
```

目前暂时用 `map` 存在内存里。

至此，阶段四的基本任务也完成了。

三个进阶任务 `AAAA MX` 都是从一开始就顺手写了的。

昨晚过于匆忙 `push` 。进一步测试，修复一些 bug 。

```shell
$ dig buck.dnspod.net @localhost
$ dig ligen131.com @localhost
$ dig ligen131.com @localhost
$ dig github.com @localhost
$ dig github.com @localhost
# 服务端输出
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

用客户端测试

```shell
$ ./digg baidu.com --server=127.0.0.1
$ ./digg baidu.com --server=127.0.0.1
# 服务端输出
[Server] Read package from 127.0.0.1:54384, length = 27
[Client] Receive UDP package from 192.5.6.30:53, length = 285
[Client] Receive UDP package from 220.181.33.31:53, length = 317
[Server] Read package from 127.0.0.1:54387, length = 27
Read cache baidu.com., len = 2
[39 156 66 10]
[110 242 68 66]
```

Timeout 机制好像需要改一改。