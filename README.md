此脚本为shadowsocks-manager服务端一键部署脚本

本脚本纯属学习用，请勿用于商业活动


### 版本介绍

服务端用到的是shadowsocks-libev版

shadowsocks-libev： [前往查看shadowsocks-libev](https://github.com/shadowsocks/shadowsocks-libev)


服务端安装的是shadowsocks-manager最新打包版本

shadowsocks-manager： [前往查看shadowsocks-manager最新版](https://github.com/quniu/shadowsocks-manager/releases)



### 安装方法

安装wget
```
# centos
yum -y install wget

# Ubuntu
apt-get -y istall wget
```

安装服务
```
rm -rf ./install.sh ./shadowsocks-manager.log
wget --no-check-certificate https://raw.githubusercontent.com/quniu/ssmgr-deploy/master/install.sh
chmod +x install.sh
./install.sh 2>&1 | tee shadowsocks-manager.log
```

### 安装说明
日志在`/root/`下面

脚本在`/root/`下面

shadowsocks-manager 安装目录在`/usr/local/`下面




### 监听端口

服务端启用端口`6001`

客户端启用端口`6002`（亦可自己定义）

客户端启用密码`需要自己填写`



### 查看shadowsocksr服务

默认安装成功之后会自动启动服务
```
service shadowsocks-manager status
service shadowsocks-manager stop
service shadowsocks-manager start
```
