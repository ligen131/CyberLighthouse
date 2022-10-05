# Cyber Lighthouse

A simple DNS query client (likes command `dig` in linux) and server (local cache server), including a light DNS message parser and generator.

## Usage

```shell
$ cd src
$ go mod download
$ go run main.go
```

It will listening on `localhost:53`.

Run following command to execute parser and generator.

```shell
$ dig google.com @localhost
```

## Build

```shell
$ mkdir build
$ cd src
$ go build main.go -o ../build/digg
```

The built file is generated into `build` folder.

## Testing

```shell
$ cd src
$ go test CyberLighthouse -v
```

## LICENSE

GNU General Public License v3.0

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
| 阶段 4 | DNS Server 非递归查询 | ❌ | -- |
| 阶段 4 | DNS Server 递归查询 | ❌ | -- |
| 阶段 4 | DNS Server【进阶】支持 AAAA MX | ❌ | -- |
| 阶段 4 | DNS Server【进阶】缓存改存储 | ❌ | -- |
| 阶段 4 | DNS Server【进阶】支持递归查询开关 | ❌ | -- |
| 阶段 4 | DNS Server【进阶】支持 TCP | ❌ | -- |
| 阶段 4 | DNS Server【进阶】支持协议更换 | ❌ | -- |
| 阶段 4 | DNS Server【进阶】支持并发 | ❌ | -- |

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