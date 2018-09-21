
## 概述

`xsec-checker`是一款服务器安全检测的辅助工具，由GO语言开发，天生支持跨平台，同一份代码可以交叉编译出linux与windows平台下的可执行文件，且无任何库的依赖。

关于跨平台说点题外话，笔者工作前7，8年一直在游戏行业，从安全、运维及开发都有涉猎，记得移动互联网兴起时，许多手机游戏都是先只支持iphone平台，后来才慢慢支持Android平台的，原因是同一款游戏的客户端，需要2个团队，一个team用objective-c开发iphone版的，另一个team用java再重写一版android平台的，到了后期的维护成本及复杂度可想而知。

当时国内最流行的手游开发框架是cocos2d-iphone，是objective-c实现的，后来王哲推出了c++版本的cocos2d-x，只写一套c++版本的代码就可以交叉编译出多种平台的客户端，极大地提高了手机游戏开发的效率。

但业内马上又出现了新的难题，因C++语言难以驾驭，靠谱的C++非常不好招而且人员成本很高，后来cocos2d-x又推出了lua与js的绑定版本，这样的话，在一个研发Team中，只需极少的C++大神就可以搭建好底层框架，具体的业务与逻辑代码，能快速上手lua与js的新手就可以做了，甚至连策划都可以上手，直接写游戏逻辑代码验证自己的设计了，减少沟通与在验证玩法时反反复复让研发修改代码的成本。

目前安全界流行使用python，笔者建议在有高性能要求、跨平台部署、无外部依赖、部署方便、源码加密等要求的场景下使用go语言，go同python一样，也是种全栈的语言。


目前实现的功能如下所示：

![](http://docs.xsec.io/images/sec_detect_tool/functions.png)

项目地址：[https://github.com/netxfly/sec_check](https://github.com/netxfly/sec_check)

## 使用说明：

- 使用帮助

```bash
$ ./main
NAME:
   xsec checker - linux and windows security detect tool

USAGE:
   main [global options] command [command options] [arguments...]

VERSION:
   20180914

AUTHOR:
   netxfly <x@xsec.io>

COMMANDS:
     info      host info
     init      init rule from yara files
     ps        list process
     netstat   list connection
     pstree    list process tree
     loginlog  list login record
     autoruns  list autoruns
     crontab   list crontab
     scan      Malicious program scanning
     dump      dump all result to json
     web       Startup a web server to view check result
     help, h   Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --debug, -d             debug mode
   --path value, -p value  yara rules path (default: "rules")
   --type value, -t value  scan type, such as: process, file (default: "process")
   --file value, -f value  File path to scan
   --verbose, --vv         verbose mode
   --server value          http server address
   --port value            http port (default: 8000)
   --help, -h              show help
   --version, -v           print the version
```

- 查看主机信息

```bash
 ./main info
{"HostInfo":{"hostname":"xxxxx","uptime":102930,"bootTime":1537410991,"procs":196,"os":"linux","platform":"centos","platformFamily":"rhel","platformVersion":"6.3","kernelVersion":"2.6.32-220.23.2.mi6.el6.x86_64","virtualizationSystem":"","virtualizationRole":"","hostid":"b5d52e45-48ee-4730-98c3-5d8b2f2de48b"},"InterfaceInfo":[{"mtu":16436,"name":"lo","hardwareaddr":"","flags":["up","loopback"],"addrs":[{"addr":"127.0.0.1/8"}]},{"mtu":1500,"name":"eth0","hardwareaddr":"fa:16:3e:75:12:f5","flags":["up","broadcast","multicast"],"addrs":[{"addr":"10.10.10.10/24"}]}]} <nil>
```

- 查看进程

![](http://docs.xsec.io/images/sec_detect_tool/ps.jpg)

- 查看网络连接

![](http://docs.xsec.io/images/sec_detect_tool/netstat.jpg)

- 查看进程树

![](http://docs.xsec.io/images/sec_detect_tool/pstree.jpg)

- 查看登录日志

![](http://docs.xsec.io/images/sec_detect_tool/login_log.jpg)

- 查看自启动项

![](http://docs.xsec.io/images/sec_detect_tool/autoruns.jpg)

- 查看crontab

![](http://docs.xsec.io/images/sec_detect_tool/crontab.jpg)

- 初始化yara规则

该命令会把当前rules目录下的所有yara规则初始化一个rules.db文件，以后需要扫描的时候，不需要再把rules目录下的一堆规则复制到机器上了，只需要把rules.db放到检测程序的当前目录下即可。

需要注意的是，不能加太多的规则，否则扫描速度太慢，建议只加常见后门的规则，保持在500条之内，（yara扫描时会占满一个cpu核心，测试通过协程并发扫描的时候，测试服务器直接无响应了2次，暂时先改回了单线程模式）。

```bash
$ ./main init
[0001]  INFO xsec checker: Init rules Done, total: 1313 rules, err: <nil>
```
- 扫描

支持对系统中运行的所有进程以及指定的文件进行扫描。
    * scan默认为对进程进行扫描
    * -vv表示表不详细模式，可以看到扫描的过程
    * --type表示显式特定扫描模式，可选参数为process与file，分别表示对进程与文件进行扫描
    * --file表示对指这定的目录或文件进行扫描

![](http://docs.xsec.io/images/sec_detect_tool/scan.jpg)

- 结果保存与查看

1. dump指定默认会将操作系统信息，进程、端口列表，autoruns、crontab、进程扫描结果等信息保存到当前目前的result.json文件中。
1. web指定表示启动一个Web server查看显示结果，暂时偷懒没有处理直接出了json（先在节前快速推出版本，以后再慢慢迭代）

![](http://docs.xsec.io/images/sec_detect_tool/dump.jpg)

![](http://docs.xsec.io/images/sec_detect_tool/web.jpg)

# 编译说明

利用`yara`规则扫描的库为`https://github.com/hillu/go-yara`，是`yara`库的go语言绑定，在使用`go-yara`之前需要先编译`yara`，笔者使用的编译平台分别为`centos 6.x`与`ubuntu 17.10`，
可以在linux平台下编译出linux与windows平台的可执行版本。

- 安装yara

笔者使用的`yara`版本为`3.7.1`，

```bash
mkdir ~/softs/
cd ~/softs/
wget https://github.com/VirusTotal/yara/archive/v3.7.1.tar.gz
tar -zxvf v3.7.1.tar.gz
cd yara-3.7.1
export YARA_SRC=~/softs/yara-3.7.1
./bootstrap.sh
./configure --disable-shared --enable-static --without-crypto
make && make install
cp ./libyara/yara.pc /usr/local/lib/pkgconfig/yara.pc
```

- 安装go-yara库

这一步不是必需的，但是可以测试能否编译通过，这里通过后，自己写的调go-yara库的程序也能编译通过。

```
go get github.com/hillu/go-yara
cd $GOPATH/src/github.com/hillu/go-yara
export YARA_SRC=/home/willem/src/yara-3.7.1
export CGO_CFLAGS="-I${YARA_SRC}/libyara/include"
export CGO_LDFLAGS="-L${YARA_SRC}/libyara/.libs -lyara -lm"
go build -tags yara_static -tags no_pkg_config --tags yara3.7
```

## 编译linux版本的可执行程序

```
cd $GOPATH/src
git clone https://github.com/netxfly/sec_check
cd sec_check
```

- Linux下编译出依赖libyara.so.3库的可执行文件，大小为12M，需要将库加到/etc/ld.so.conf中并用ldconfig -v刷新

```bash
go build --tags yara_static --tags no_pkg_config --tags yara3.7 main.go
```

- Linux下编译出不依赖任何库的可执行文件，大小为13M

```bash
go build --ldflags '-extldflags "-static -lm"' --tags yara_static --tags no_pkg_config --tags yara3.7 main.go
```

注：

1. 在编译的过程中，提示缺少go包时，直接按错误提示显示的包名，利用`go get`指令安装即可
2. 如果提示`cannot find -lpthreads`，直接用`yum install glibc-static 安装`
3. 上面第1条指令编译出来的可执行程序不带libyara.so.3，需要把libyara.so.3上传到目标服务器中，然后手工加入
4. 上面第2条编译指令可以编译出不依赖任何包的可执行程序，但在centos 6.x与 centos 7.x要分别编译，否则6.x下编译出来的没法在7.x下运行，反之也一样

## 编译windows可执行程序

笔者的编译平台的`ubuntu 17.10`

- 安装yara
```
apt-get update
apt-get install gcc-mingw-w64
cd ${YARA_SRC} \
  && ./bootstrap.sh \
  && ./configure --host=x86_64-w64-mingw32 --disable-magic --disable-cuckoo --without-crypto --prefix=${YARA_SRC}/x86_64-w64-mingw32 \
  && make -C ${YARA_SRC} \
  && make -C ${YARA_SRC} install
```

- 编译windows下的可执行文件
```
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
PKG_CONFIG_PATH=${YARA_SRC}/x86_64-w64-mingw32/lib/pkgconfig \
go build -ldflags '-extldflags "-static"' --tags yara_static --tags no_pkg_config --tags yara3.7 main.go
```

