#!/bin/bash

## Linux下编译出依赖libyara.so.3库的可执行文件，大小为12M，需要将库加到/etc/ld.so.conf中并用ldconfig -v刷新
# go build --tags yara_static --tags no_pkg_config --tags yara3.7 main.go

#Linux下编译出不依赖任何库的可执行文件，大小为13M
# go build --ldflags '-extldflags "-static -lm"' --tags yara_static --tags no_pkg_config --tags yara3.7 main.go

## windows下编译出可执行的Exe文件
# GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
# PKG_CONFIG_PATH=${YARA_SRC}/x86_64-w64-mingw32/lib/pkgconfig \
# go build -ldflags '-extldflags "-static"' --tags yara_static --tags no_pkg_config --tags yara3.7 main.go