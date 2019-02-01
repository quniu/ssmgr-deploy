此脚本为shadowsocks-manager服务端一键部署脚本

### 版本介绍

服务端用到的是shadowsocks-libev[查看最新版](https://github.com/shadowsocks/shadowsocks-libev/releases)

服务端安装的是shadowsocks-manager[查看最新版](https://github.com/shadowsocks/shadowsocks-manager)


### 安装方法

安装wget
```
# centos
yum -y install wget

# Ubuntu
apt-get -y install wget
```

下载脚本
```
rm -rf ./install.sh ./shadowsocks-manager.log
wget --no-check-certificate https://raw.githubusercontent.com/quniu/ssmgr-deploy/master/install.sh
chmod +x install.sh
./install.sh 2>&1 | tee shadowsocks-manager.log
```


### 功能
- 安装shadowsocks-manager服务
- 设置固定时间自动重启（选最后一项）



### 安装说明
日志在`/root/`下面

脚本在`/root/`下面

shadowsocks-manager 安装目录在`/usr/local/`下面



### 监听端口

服务端启用端口`6001`

客户端启用端口`6002`（亦可自己定义）

客户端启用密码`需要自己填写`



### 查看shadowsocks服务

默认安装成功之后会自动启动ss服务,重启也会自动启动ss服务
```
# status stop start restart
/etc/init.d/shadowsocks-manager status
```

本脚本纯属学习用，请勿用于商业活动
