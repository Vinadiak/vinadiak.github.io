# 如何重打包及调试harmony

作者:Vinadiak. (感谢Redbud-xuanxuan)

## 环境

工具:binwalk,gdb-multiarch

系统:ubuntu16.04 or ubuntu 20（系统推荐)

# 重打包步骤

1.根据https://gitee.com/singularsecuritylab/open-harmony-emulator配置好环境

2.用binwalk将rootfs.img的文件系统取出 

​    binwalk -Me rootfs.img

3.将你需要存放的文件放入文件系统

4. mkfs.jffs2 -d rootfs/ -o rootfs.jffs2 将文件系统进行重打包得到镜像文件rootfs.jffs2
5. 将rootfs.jffs2重命名为rootfs.img（因为harmony只认识rootfs.img)

# 调试步骤

```shell
vim start_qemu.sh  加入选项-S -s进行调试
sh start_qemu.sh
gdb-multiarch 
set architecture arm #（必须要)
target remote :1234 #即可调试整个qemu
#在 harmofs1 里给出main函数地址,x/50i main_addr可查看即可完成调试
```