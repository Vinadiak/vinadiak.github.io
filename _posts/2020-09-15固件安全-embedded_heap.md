---
layout: post
title: 固件安全-embedd_heap
description: 学习固件安全中的heap,持续更新....
categories:  固件安全
---



# 固件安全

## 前言

本篇是我学习固件安全的技术笔记，包括我遇到的问题，以及解决的方式

## 工具

常用工具:

1.qemu

2.IDA

3.Ghidra



# 如何用qemu-system-mips 启动embedd_heap

1.传文件到qemu

宿主机 ifconfig tap0 10.0.0.1 qemu要ifconfig eth0 ip 10.0.0.2

宿主机用python -m SimpleHttpserver 8080 启动一个简单的http服务

qemu用wget IP：8080/*.tar.gz 获取文件，80%要压缩文件

2.解压到qemu中，然后将elf文件目录下的lib扔到/lib,然后chmod 777 /lib/*

然后启动./embedd_heap就可以了



# 搭建MIPS环境

https://blog.csdn.net/u012763794/article/details/82750102

https://e3pem.github.io/2019/08/23/mips-pwn/mips-pwn%E7%8E%AF%E5%A2%83%E6%90%AD%E5%BB%BA/

## 1.堆溢出-embedd_heap

### 逻辑分析

main函数：

1.update：更新堆的size,填充内容

2.view: 查看堆的内容

3.pwn:continuous delete two heap  并且update heap
 ![](/images/character5/firm1.png)




Update:通过update我们可以看到，我们可以填入size，并且输入跟size大小相同的内容，同时这里有个堆溢出的漏洞，因为我们输入完size之后，该heap并没有重新calloc相同size的大小，主要我们分配的size比之前的大，那我们就可以进行堆溢出

 ![](/images/character5/firm2.png)


![](/images/character5/firm3.png)


view：就是输出heap对应size的内容

![](/images/character5/firm5.png)

del：free heap，同时将heap所对应的指针置0，也就是说没有UAF


![](/images/character5/firm5.png)


## 思路

固件一般使用ulibc,可认为是旧版的glibc,只要我们





# 尚存在的问题

qemu-system-mode存在gdbserver无法监听端口的问题
