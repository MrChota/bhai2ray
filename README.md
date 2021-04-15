## v2ray based on Nginx VMESS + WS + TLS one-click installation script

> Thanks to JetBrains provided by non-commercial open source software development authorization

> Thanks for Non-Commercial Open Source Development Authorization by JetBrains
### Telegram group
* Telegram exchange group: https: t.me/bhaifoundation
* Telegram update announcement channel: https: t.me/bhaifoundation

### Ready to work
* Prepare a domain name and add a record to a record.
* [V2ray official description] (https://www.v2ray.com/), learn about TLS WebSocket and V2Ray
* Install wget

### Installation / Update mode (H2 and WS version have been merged)
VMESS + WebSocket + TLS + Nginx + Website
`` `
Wget -n --no-check-certificate -q-install.sh "https://RAW.GITHUBUSERCONTENT.COM/MrChota/bhai2ray/master/install.sh" && chmod + x install.sh && bash install .sh
`` `

### Precautions
* If you don't understand the specific meaning of the settings in the script, in addition to the domain name, use the default value provided by the script.
* Using this script requires you to have Linux foundations and experience, understand the knowledge of computer network, computer basic operation
* Currently supporting Debian 9+ / Ubuntu 18.04+ / CentOS7 +, some CentOS templates may have difficulty in processing compilation. It is recommended to change to other system templates when compiling.
* The group owner only provides extremely limited support, if you have any questions, you can ask the group of friends.
* At 3 o'clock in the morning of Sunday, Nginx will automatically restart to cooperate with the certificate of the certificate. During this period, the node cannot be connected normally, and the expected duration is several seconds to two minutes.

### Update log
> Update Content, please see Changelog.md

### Thank you
* ~~ This script is another branch address: https://github.com/dylanbai8/v2ray_ws-tls_website_onekey Please choose according to the requirements ~~ The author may have stopped maintaining
* This script in the MtProxy-Go TLS version item reference https://github.com/whunt1/onekeymakemtg Thank Whunt1
* This script is sharp 4 in 1 script original item reference https://www.94ish.me/1635.html thank you
* This script is sharp 4 in 1 script modified project reference https://github.com/ylx2016/linux-netspeed Thank y 202016

### Certificate
> If you already have a certificate file you use, you can name the CRT and Key files v2ray.crt v2ray.key in / data directory (if you don't exist, please create a directory), please note the certificate file permission And the validity period of the certificate, please renew it after the custom certificate is expired.

Script support automatically generates a Let's encrypted certificate, valid for 3 months, theoretically generated certificate support automatic renewal

### View client configuration
`Cat ~ / v2ray_info.txt`

Introduction to ### v2ray

* V2ray is an excellent open source network agent tool that can help you experience the Internet, and it has been fully supported by Windows, Mac, Android, iOS, Linux and other operating systems.
* This script is a fully configured script. After all the processes are running normally, they can set the client directly according to the output results.
* Please note: We still strongly recommend that you understand the workflow and principle of the entire program all.

### 建议 Single server only sets a single agent
* This script is default the latest version of the latest version of V2Ray Core
* V2ray core is currently the latest version of 4.22.1 (at the same time note the synchronous update of client Core, you need to ensure the core version of the client "= server core version)
* It is recommended to use the default 443 port as the connection port.
* The camouflage content can be replaced by themselves.

### Precautions
* Recommended this script in a pure environment, if you are a newbie, please do not use the CentOS system.
* Do not apply this program to the production environment before trying this script.
* This program relies on Nginx implementation related features, please use [LNMP] (https://lnmp.org) or other similar to carry NGINX scripts to install NGINX, using this script, can cause unpredictable errors (not tested If there is, subsequent versions may handle this issue).
* V2ray partial features depend on the system time, make sure that the system UTC time error of the V2RAY program is not related to the time zone.
* This BASH is based on [V2RAY official installation script] (https://install.direct/go.sh) and [attme.sh] (https://github.com/neilpang/acme.sh) work.
* CentOS system users please release the program related port in the firewall (default: 80, 443)


### Starting method

Start V2ray: `Systemctl Start V2ray`

Stop V2ray: `Systemctl Stop V2ray`

Start nginx: `systemctl start nginx`

Stop nginx: `systemctl stop nginx`

### Related Directory

Web directory: `/ home / wwwroot / 3dcelist`

V2RAY server configuration: `/ etc / v2ray / config.json`

V2RAY client configuration: `~ / v2ray_info.inf`

Nginx directory: `/ etc / nginx`

Certificate file: `/data/v2ray.key and / data / v2ray.crt` please pay attention to the certificate permission setting

