GGVPacker
=========

使用方法
--------
可以用来加密和解密nc1020/nc2000/nc3000的bin格式应用.  
解密时候根据后缀可以输入机身内格式和带属性格式.  
加密时候用带属性格式从属性中读取机身文件名, 使用机身内格式可以手动指定程序名称, 如果没有指定, 再从文件名获取. 程序名称最长10个字节.  

GGVPacker input.bin output.tmp -decode  
解密(带目录和属性)  
GGVPacker input.bin output.cod -decode  
解密(机身内格式)  

GGVPacker input.bin output.bin  
加密, 支持机身内格式(从文件名生成程序名称)和带目录的格式输入文件(目录自带程序名称).  
GGVPacker input.bin output.bin appname  
加密机身格式并手动指定程序名称.  


免责声明
--------
此工具仅供研究和学习使用, 请勿将其用于商业用途. 

