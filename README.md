# FilesDumper

游戏文件转储工具

## 功能
- 1、对CreateFileA函数进行hook并转储其读取的文件到游戏目录的dumpfiles文件夹
- 2、在FilesDumper.ini可配置黑名单或白名单模式(过滤文件的后缀名)

## 使用方法
安装Visual Studio 2022后运行build.bat编译，然后<br>
使用CFF Explorer导入dll。

## 适用场景
- [【おちょ工房】猫と幼馴染と三日間](https://vndb.org/v30161) : ysbin.ypf不在目录内而是内嵌在exe里，且用garbro和ResourceHacker无法提取
