##V2Ray is based on Nginx's vmess-ws-tls one-click installation script
Thanks to JetBrains for your non-commercial open source software development license

Thanks for non-commercial open source development authorization by JetBrains

Telegram group
telegram communication group:https://t.me/wulabing_v2ray
telegram updates the announcement channel:https://t.me/wulabing_channel
Preparations
Prepare a domain name and add an A record.
V2ray official instructions for TLS WebSocket and V2ray-related information
Install the wget
How to install/update (h2 and ws versions merged)
Vmess+websocket+TLS+Nginx+Website

wget -N --no-check-certificate -q -O install.sh "https://raw.githubusercontent.com/wulabing/V2Ray_ws-tls_bash_onekey/master/install.sh" && chmod +x install.sh && bash install.sh
Precautions
If you don't know what the settings in the script mean, use the default values provided by the script, in addition to the domain name
Using this script requires that you have the basics and experience of Linux, understand part of the computer network knowledge, computer basic operations
Currently supports Debian 9 plus / Ubuntu 18.04 plus / Centos7 plus, some Centos templates may have difficulty handling compilation issues, it is recommended that you replace the compilation problem with other system templates
Group owners provide very limited support and can ask group friends if they have questions
Every Sunday at 3 a.m., Nginx automatically restarts to coincide with the certificate-issuing scheduling task, during which time the node is unable to connect properly and is expected to last from a few seconds to two minutes
Update the log
For updates, check out the CHANGELOG.md

##Acknowledgement
Another branch version of this script (Use Host) address: https://github.com/dylanbai8/V2Ray_ws-tls_Website_onekey Select as needed The author may have stopped maintenance
The MTProxy-go TLS version of the project reference in this script https://github.com/whunt1/onekeymakemtg thanks to whunt1 here
In this script, sharp 4 in 1 script original project reference https://www.94ish.me/1635.html thanks here
In this script, Sharp 4 in 1 script modified project reference https://github.com/ylx2016/Linux-NetSpeed thanks here for ylx2016
certificate
If you already have a certificate file for the domain name you are using, you can place the crt and key files v2ray.crt v2ray .key in the /data directory (please build the directory first if the directory does not exist), please note the certificate file permissions and certificate expiration date, custom certificate expiration date please renew yourself

Scripts support automatic generation of let's encrypted certificates, valid for 3 months, and theoretically auto-generated certificates support automatic renewal

View the client configuration
cat ~/v2ray_info.txt

Introduction to V2ray
V2Ray是一个优秀的开源网络代理工具，可以帮助你畅爽体验互联网，目前已经全平台支持Windows、Mac、Android、IOS、Linux等操作系统的使用。
This script is a one-click fully configured script that can be used by setting up the client directly according to the output results once all the processes are up and running
Please note: We still strongly recommend that you understand the workflow and principles of the entire program in its entirety
It is recommended that a single server set up only a single agent
This script installs the latest version of V2ray core by default
The latest version of V2ray core is currently 4.22.1 (also note that the client core is updated synchronously and that the client kernel version is guaranteed to be >- the service-side kernel version)
The default 443 port is recommended as the connection port
Disguised content can be replaced on its own.
Precautions
It is recommended to use this script in a pure environment, if you are new to the system, please do not use the Centos system.
Do not apply this program to a production environment until you try that it is actually available.
The program relies on Nginx for related functionality, so be aware that users who have installed Nginx using LNMP or other similar Nginx scripts may cause unpredictable errors (untested, if present, subsequent versions may handle this issue).
Part of V2Ray's functionality depends on system time, so make sure that the system UTC time error you use with the V2RAY program is within three minutes, regardless of the time zone.
This bash relies on V2ray official installation scripts and acme.sh work.
Centos system users should pre-release program-related ports in the firewall (default: 80,443)
How to start
Start V2ray:systemctl start v2ray

Stop V2ray:systemctl stop v2ray

Start Nginx:systemctl start nginx

Stop Nginx:systemctl stop nginx

Related directories
Web directory:/home/wwwroot/3DCEList

V2ray service side configuration:/etc/v2ray/config.json

V2ray client configuration: ~/v2ray_info.inf

Nginx Catalog: /etc/nginx

Certificate file: Note the certificate permission settings/data/v2ray.key 和 /data/v2ray.crt

donation
Virtual currency donations are currently supported through MugglePay

Wulabing invites you to use Muggle Bao, based on Telegram's e-wallet, to pay an anonymous fee of 0 seconds. https://telegram.me/MugglePayBot?start=T3Y78AZ3

You can donate anonymously to me via Telegram: send /pay @wulabing xxx to @MugglePayBot to the default currency is USDT

If you need to donate via Alipay/WeChat, please @wulabing thank you for your support
