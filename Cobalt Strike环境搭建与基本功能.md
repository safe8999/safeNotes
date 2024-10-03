Cobalt Strike基于Java环境开发，所以一定要安装Java环境。（工具的组成为服务端 + 客户端）

Cobalt Strike4.8

### 服务端  
启动Cobalt Strike需要JDK的支持，需要安装Java环境，如果服务端是kali，默认安装了java环境  
文件复制进linux服务器  
执行`ls -l` 查看TeamServer跟TeamServerImage是否有执行权限  
如果TeamServer跟TeamServerImage不具备x执行权限，执行如下命令添加执行权限  
`sudo chmod +x teamserver TeamServerImage`  
启动服务端：  
`sudo ./teamserver 192.168.163.172 cspasswd`  
这里填本机ip地址跟密码,默认端口为50050  
![alt text](image/server.png)

### 客户端  
windows运行客户端，也需要有JDK环境  
运行cobaltstrike-client.cmd文件  
输入对应服务端上设置的Host Port User Password  

![alt text](image/image-1.png)  
Alias：输入主机别名或使用默认值，不能为空或以*开头。  
Host：指定团队服务器的IP地址，不能为空  
Port：服务器的端口（默认为50050）  
User：你在团队服务器上的昵称，不能为空。  
Password：连接到服务器的密码  

第一次用连接到此团队服务器, 会弹出确认指纹  
Cobalt Strike将询问你是否识别此团队服务器的SHA256哈希,指纹校验的主要作用是防篡改  
点击是,连接登录到服务端并打开客户端用户界面   

![alt text](image/image-2.png)  

![alt text](image/image-4.png)  

如果连接不上，查看服务端防火墙是否开启默认端口或者指定的端口  

Cobalt Strike将会记住这个SHA256哈希值,以便将来连接.可以通过Cobalt Strike -> Preferences -> Fingerprints 来管理这些哈希值。  


## 隐藏特征码-服务端(免杀手法之一)  
开启禁Ping动作、修改CS默认端口、修改CS默认证书、C2profile混淆流量、nginx反向代理

#### 开启禁Ping动作:  
        命令: sudo vim /etc/sysctl.conf
        添加一行: net.ipv4.icmp_echo_ignore_all = 1
        刷新配置: sudo sysctl -p

#### 修改CS默认端口:  
        cd到cs服务端: cd CobaltStrike4.8/Server
        编辑teamserver文件: vim teamserver
        修改port=50050为其他端口
        如果有防火墙记得开放规则: sudo ufw allow 19001

#### 修改CS默认证书:    
Cobalt Strike默认证书中含有与cs相关的特征，已经被waf厂商标记烂了，我们要重新生成一个新的证书，这里我们用JDK自带的keytool证书工具来生成新证书 

删除服务端Server目录下的cobaltstrike.store文件:  
`sudo rm -rf cobaltstrike.store`   

利用keytool生成新的一个无特征的证书文件cobaltstrike.store  
    `keytool -keystore cobaltstrike.store -storepass 123456 -keypass 123456 -genkey -keyalg RSA -alias 360.com -dname "CN=Microsoft Windows, OU=MOPR, O=Microsoft Corporation, L=Redmond, ST=Washington, C=US"`  
    -keystore 生成的store名  
    -storepass 指定更改密钥库的储存口令  
    -keypass 指定更改条目的密钥口令  
    -genkey -keyalg RSA 指定算法  
    -alias 自定义别名  
    -dname 指定所有者信息  

证书生成完毕后，查看一下是否是新的证书内容   
查看cs证书文件内容：`sudo keytool -list -v -keystore cobaltstrike.store`    

#### C2profile混淆流量:  
Github上已经有非常多优秀的C2-Profile可以供我们使用了，我们需要使用Profile让Beacon和Teamserver之间的交互看起来尽可能像正常的流量  

https://github.com/rsmudge/Malleable-C2-Profiles  
https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/normal/amazon.profile  
https://github.com/threatexpress/malleable-c2    

修改Beacon与cs通信时候的流量特征，创建一个c2.profile文件(名字任意)   
`sudo touch c2.profile`  

​这里我使用的是后者jquery的profile
把jquery-c2.4.8.profile的内容复制进c2.profile，可自由修改部分内容:   
`sudo vim c2.profile`    

然后使用c2.profile方式启动teamserver   
`sudo ./teamserver 192.168.2.96 passwd332 c2.profile`   

客户端开启CS的监听，触发木马   
抓包，查看流量特征是否被混淆   
发现请求改成了我们在c2.profile中编写的URL、UA等信息时，则修改成功。   

#### 部署nginx反向代理:   
nginx反向代理可以用来隐藏C2服务器，把cs监听端口给隐藏起来了，要不然默认geturl就能获取到我们的shellcode，加密shellcode的密钥又是固定的(3.x 0x69，4.x 0x2e)，所以能从shellcode中解出c2域名等配置信息。  

不修改这个特征的话nmap 一扫就出来  
`nmap [ip][port] --script=grab_beacon_config.nse`  

修改这个特征有两个方法:  
1.修改源码加密的密钥  

2.限制端口访问，让一般的扫描器扫不出来  

这里我们用nginx做反向代理，通过ua过滤流量，然后防火墙限制端口只能让127.0.0.1访问shellcode端口

先到我们的服务器上安装nginx服务，kali自带  

找到nginx安装路径:`whereis nginx`  

打开nginx配置文件 `vim /etc/nginx/sites-available/default` kali自带的nginx配置文件在这个位置，具体看个人的nginx安装位置  

在http中的server中配置中添加   

        location ~*jquery {
            if ( $http_user_agent != "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko")
            {
                return 404;
            }
            proxy_pass http://127.0.0.1:12095;
        }

配置中的ua根据你的profile文件中设置的useragent所定，profile中的ua也可以自行修改  
重启nginx: `sudo service nginx restart`

设置防火墙只能让127.0.0.1访问监听端口  

        iptables -I INPUT -p TCP --dport 12095 -j DROP
        iptables -I INPUT -s 127.0.0.1 -p TCP --dport 12095 -j ACCEPT
        service iptables restart

杀毒软件查杀方式：特征码、动态查杀、云查杀  


### Cobalt Strike工作原理   
        1.攻击者通过Cobalt Strike生成恶意软件,并将其上传到受害者计算机上。
        2.恶意软件会在受害者计算机上运行,并向Cobalt Strike服务器发送连接请求。
        3.Cobalt Strike服务器接受连接请求，并与恶意软件建立通信。
        4.攻击者可以通过Cobalt Strike控制台执行各种操作,如扫描目标网络、收集目标计算机信息、下载和上传文件等。
        5.Cobalt Strike还提供了内置的模块,如端口转发、代理服务器、漏洞利用等,可帮助攻击者更好地渗透目标网络。
