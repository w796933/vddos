#!/bin/bash

if [ $(id -u) != "0" ]; then
	echo 'ERROR! Please "su root" and try again!
	'
	exit 0
fi
# Kiểm tra có cài vDDoS chưa
if [ ! -f /vddos/vddos ]; then
	echo 'ERROR! Please install vDDoS Protection Service!
'
	exit 0
fi

if [ ! -f /usr/bin/curl ]; then
	yum -y install curl >/dev/null 2>&1
	echo 'ERROR with curl! Please Try Again!
'
	exit 0
fi

if [ ! -f /usr/bin/jq ]; then
	curl -L https://github.com/duy13/vDDoS-Layer4-Mapping/raw/master/jq-1.5-linux64 -o /usr/bin/jq --silent
	chmod 755 /usr/bin/jq
fi

clear
####################################
	echo '
   Welcome to vDDoS, a HTTP(S) DDoS Protection Reverse Proxy. Thank you for using!

	Please choose vDDoS Layer 4 Running Mode:

	 CloudFlare Mode:
 	  1. Enable Captcha-All-Country Mode (Recommend This Mode For Large DDoS Attacks)
	  2. Enable Monitor-vDDoS-logs-and-Captcha Mode
	  3. Enable Monitor-vDDoS-logs-and-Block Mode
	  4. Remove all rules exist on CloudFlare Firewall

	 CSF Mode:
	  5. Enable Monitor-vDDoS-logs-and-Block Mode
	  6. Remove all rules exist on CSF

	 End & Exit:
	  7. End All Process (Kill all Process Mode Running)
	  8. Exit
	'
echo -n 'Enter Your Answer [1, 2, 3... or 8]: '
read vDDoSLayer4Mode




############# Nếu chọn 1. Enable Captcha-All-Country Mode
if [ "$vDDoSLayer4Mode" = "1" ] ; then
	clear
	echo 'Captcha-All-Country Mode:'
	echo 'Please Go to CloudFlare.com and register an account:
	'
	echo -n 'Enter Your CloudFlare USERNAME [somebody@your-domain.com]: '
	read EmailCloudFlare
	echo -n 'Enter Your CloudFlare Global API-KEY [s0methin9key******]: '
	read APIKEYCloudFlare
	echo -n 'Enter Your CloudFlare ZONE-ID [s0methin9id**************]: '
	read ZONEKEYCloudFlare


	apikey=$APIKEYCloudFlare
	zone=$ZONEKEYCloudFlare
	email=$EmailCloudFlare
	countrylist_willcaptcha='/vddos/layer4-mapping/cf/captcha-all-country/countrylist-willcaptcha.txt'
	if [ ! -f /vddos/layer4-mapping/cf/captcha-all-country/countrylist-willcaptcha.txt ]; then
		mkdir -p /vddos/layer4-mapping/cf/captcha-all-country/
		curl -L https://github.com/duy13/vDDoS-Layer4-Mapping/raw/master/countrylist-willcaptcha.txt -o $countrylist_willcaptcha --silent
	fi
	################### Captcha cho country:
	ten_file_chua_list=$countrylist_willcaptcha
	echo "`cat $ten_file_chua_list | grep .`" > $ten_file_chua_list
	so_dong_file_chua_list=`cat $ten_file_chua_list | grep . | wc -l`
	dong=1

	while [ $dong -le $so_dong_file_chua_list ]
	do
		delaytime=$(( $RANDOM % 15 ))
		countrycaptcha_hientai=$(awk " NR == $dong " $ten_file_chua_list)
		(sleep $delaytime; curl -sSX POST "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules" \
		-H "X-Auth-Email: $email" \
		-H "X-Auth-Key: $apikey" \
		-H "Content-Type: application/json" \
		--data "{\"mode\":\"challenge\",\"configuration\":{\"target\":\"country\",\"value\":\"$countrycaptcha_hientai\"},\"notes\":\"Captcha by vDDoS Proxy Protection\"}" >/dev/null 2>&1 & )&

		echo "Add catpcha for country: $countrycaptcha_hientai"
		dong=$((dong + 1))
	done
	sleep 15
	echo 'Captcha all '$so_dong_file_chua_list' Country on CloudFlare Firewall! (You can try again if CloudFlare Firewall does not have enough '$so_dong_file_chua_list' Country)
	'
	echo -n 'Press Enter to Back:'
	read Enter
	/usr/bin/vddos-layer4

fi


############# Nếu chọn 2. Enable Monitor-vDDoS-logs-and-Captcha Mode
if [ "$vDDoSLayer4Mode" = "2" ] ; then
	clear
	echo 'Please Go to CloudFlare.com and register an account:
	'
	echo -n 'Enter Your CloudFlare USERNAME [Ex: somebody@your-domain.com]: '
	read EmailCloudFlare
	echo -n 'Enter Your CloudFlare Global API-KEY [Ex: s0methin9key******]: '
	read APIKEYCloudFlare
	echo -n 'Enter Your CloudFlare ZONE-ID [Ex: s0methin9id**************]: '
	read ZONEKEYCloudFlare
	echo -n 'Enter Your Website you want to monitor [Ex: your-domain.com]: '
	read DomainName

	if [ "$EmailCloudFlare" = "" ] || [ "$APIKEYCloudFlare" = "" ] || [ "$ZONEKEYCloudFlare" = "" ] || [ "$DomainName" = "" ]; then
		echo 'ERROR! Please Try Again!
		'
		echo -n 'Press Enter to Back:'
		read Enter
		/usr/bin/vddos-layer4
	fi

	file_chua_ip_log="/var/log/vddos/444.log"
	if [  ! -f $file_chua_ip_log ]; then
		echo 'ERROR! File '$file_chua_ip_log' not found!
		'
		echo -n 'Press Enter to Back:'
		read Enter
		/usr/bin/vddos-layer4
	fi
	echo '
Time between to loops scan IP: 
	5 (5 second) - be careful when using
	10 (10 second)
	30 (30 second) - recommend
	60 (60 second) 
	'
	echo -n 'Enter Your choose [default 30]: '
	read Time
	if [ "$Time" = "" ] ; then
		Time=30
	fi
	echo '
Prefix IP Range to Captcha: 
	no (Captcha for exactly IP Attacker x.x.x.x) - if your server under attack by ~ 1000 IP Bots
	24 (Captcha for range IP Attacker x.x.x.x/24) - recommend
	16 (Captcha for range IP Attacker x.x.x.x/16)
	'
	echo -n 'Enter Your choose [default no]: '
	read Prefix
	mkdir -p /vddos/layer4-mapping/cf/$DomainName/catpcha/
	file_chua_ip_log="/var/log/vddos/444.log"
	file_chua_ip_cu="/vddos/layer4-mapping/cf/$DomainName/catpcha/Exist-Blocked.txt"
	file_chua_ip_tam="/vddos/layer4-mapping/cf/$DomainName/catpcha/TMP.txt"
	file_chua_ip_please_block="/vddos/layer4-mapping/cf/$DomainName/catpcha/Please-Block-This-IP.txt"

	echo > $file_chua_ip_log
	echo > $file_chua_ip_cu
	echo > $file_chua_ip_tam
	echo > $file_chua_ip_please_block

	if [ "$Prefix" = "16" ] ; then
		Prefix=16

		apikey=$APIKEYCloudFlare
		zone=$ZONEKEYCloudFlare
		email=$EmailCloudFlare

		################### Cho ra full thông tin lan dau tien:
		fullrawinfo=`curl --silent -X GET "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules?match=all" \
		     -H "X-Auth-Email: $email" \
		     -H "X-Auth-Key: $apikey" \
		     -H "Content-Type: application/json"`
		fullinfo=`echo "$fullrawinfo"|jq .`

		################### Cho ra tổng số rule lau dau tiên:
		numberrule=`echo "$fullinfo"| grep "total_count"|awk {'print $2'}`
		#echo "Tong rule la: $numberrule"
		so_rule_cf_ban_dau_co=$numberrule



		lapmaimai='lapmaimai';
		donglon=1
		while [ $lapmaimai = 'lapmaimai' ]
		do 

			################### Cho ra full thông tin khac nhau trong moi vong lap lớn:



			cat $file_chua_ip_log | grep 444 |awk {'print $1'} | tr . " "| awk '{print $1"."$2"."0"."0"/"'$Prefix'}' |awk '!x[$0]++' > $file_chua_ip_tam;

			cat $file_chua_ip_tam > $file_chua_ip_please_block;

			phat_hien_ip_moi=`cat $file_chua_ip_please_block|wc -l`
			if [ "$phat_hien_ip_moi" != "0" ] ; then
				
				ten_file_chua_list=$file_chua_ip_please_block
				echo "`cat $ten_file_chua_list | grep .`" > $ten_file_chua_list
				so_dong_file_chua_list=`cat $ten_file_chua_list | grep . | wc -l`
				################### Xoa toan bo ID Rules:

				dong=1
				while [ $dong -le $so_dong_file_chua_list ]
				do

				################### Xóa id rule hiện tại:
					thoigiantre=$((so_dong_file_chua_list/Time+1))
					delaytime=$(( $RANDOM % $thoigiantre )) # random từ 1 tới sodong/thoigianlap
					ipcaptcha_hientai=$(awk " NR == $dong " $ten_file_chua_list)

					(sleep $delaytime; curl -sSX POST "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules" \
										-H "X-Auth-Email: $email" \
										-H "X-Auth-Key: $apikey" \
										-H "Content-Type: application/json" \
										--data "{\"mode\":\"challenge\",\"configuration\":{\"target\":\"ip_range\",\"value\":\"$ipcaptcha_hientai\"},\"notes\":\"Captcha by vDDoS Proxy Protection\"}" >/dev/null 2>&1 & )&

					dong=$((dong + 1))
				done
			fi


			echo > $file_chua_ip_log; # Xoa file goc chua log de ghi IP moi
			sleep $Time;
			# Get thong tin de bao cao:
			fullrawinfo=`curl --silent -X GET "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules?match=all" \
			     -H "X-Auth-Email: $email" \
			     -H "X-Auth-Key: $apikey" \
			     -H "Content-Type: application/json"`
			fullinfo=`echo "$fullrawinfo"|jq .`
			numberrule=`echo "$fullinfo"| grep "total_count"|awk {'print $2'}`
			tong_so_rule_cf_hien_co=$numberrule
			tong_so_rule_cf_da_them_duoc=$((tong_so_rule_cf_hien_co-so_rule_cf_ban_dau_co))

			donglon=$((donglon + 1))
			clear
			echo '
			Scan '$donglon' Times:

		Detect new IP Range to CAPTCHA: '$phat_hien_ip_moi' IP Range /'$Prefix'
		Total CAPTCHA: '$tong_so_rule_cf_da_them_duoc' IP Range
			'
			lapmaimai='lapmaimai';
		done

	else
	if [ "$Prefix" = "24" ] ; then
		Prefix=24
		apikey=$APIKEYCloudFlare
		zone=$ZONEKEYCloudFlare
		email=$EmailCloudFlare

		################### Cho ra full thông tin lan dau tien:
		fullrawinfo=`curl --silent -X GET "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules?match=all" \
		     -H "X-Auth-Email: $email" \
		     -H "X-Auth-Key: $apikey" \
		     -H "Content-Type: application/json"`
		fullinfo=`echo "$fullrawinfo"|jq .`

		################### Cho ra tổng số rule lau dau tiên:
		numberrule=`echo "$fullinfo"| grep "total_count"|awk {'print $2'}`
		#echo "Tong rule la: $numberrule"
		so_rule_cf_ban_dau_co=$numberrule



		lapmaimai='lapmaimai';
		donglon=1
		while [ $lapmaimai = 'lapmaimai' ]
		do 

			################### Cho ra full thông tin khac nhau trong moi vong lap lớn:



			cat $file_chua_ip_log | grep 444 |awk {'print $1'} | tr . " "| awk '{print $1"."$2"."$3"."0"/"'$Prefix'}' |awk '!x[$0]++' > $file_chua_ip_tam;

			cat $file_chua_ip_tam > $file_chua_ip_please_block;

			phat_hien_ip_moi=`cat $file_chua_ip_please_block|wc -l`
			if [ "$phat_hien_ip_moi" != "0" ] ; then
				
				ten_file_chua_list=$file_chua_ip_please_block
				echo "`cat $ten_file_chua_list | grep .`" > $ten_file_chua_list
				so_dong_file_chua_list=`cat $ten_file_chua_list | grep . | wc -l`
				################### Xoa toan bo ID Rules:

				dong=1
				while [ $dong -le $so_dong_file_chua_list ]
				do

				################### Xóa id rule hiện tại:
					thoigiantre=$((so_dong_file_chua_list/Time+1))
					delaytime=$(( $RANDOM % $thoigiantre )) # random từ 1 tới sodong/thoigianlap
					ipcaptcha_hientai=$(awk " NR == $dong " $ten_file_chua_list)

					(sleep $delaytime; curl -sSX POST "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules" \
										-H "X-Auth-Email: $email" \
										-H "X-Auth-Key: $apikey" \
										-H "Content-Type: application/json" \
										--data "{\"mode\":\"challenge\",\"configuration\":{\"target\":\"ip_range\",\"value\":\"$ipcaptcha_hientai\"},\"notes\":\"Captcha by vDDoS Proxy Protection\"}" >/dev/null 2>&1 & )&

					dong=$((dong + 1))
				done
			fi


			echo > $file_chua_ip_log; # Xoa file goc chua log de ghi IP moi
			sleep $Time;
			# Get thong tin de bao cao:
			fullrawinfo=`curl --silent -X GET "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules?match=all" \
			     -H "X-Auth-Email: $email" \
			     -H "X-Auth-Key: $apikey" \
			     -H "Content-Type: application/json"`
			fullinfo=`echo "$fullrawinfo"|jq .`
			numberrule=`echo "$fullinfo"| grep "total_count"|awk {'print $2'}`
			tong_so_rule_cf_hien_co=$numberrule
			tong_so_rule_cf_da_them_duoc=$((tong_so_rule_cf_hien_co-so_rule_cf_ban_dau_co))

			donglon=$((donglon + 1))
			clear
			echo '
			Scan '$donglon' Times:

		Detect new IP Range to CAPTCHA: '$phat_hien_ip_moi' IP Range /'$Prefix'
		Total CAPTCHA: '$tong_so_rule_cf_da_them_duoc' IP Range
			'
			lapmaimai='lapmaimai';
		done

	else
		Prefix=1

		apikey=$APIKEYCloudFlare
		zone=$ZONEKEYCloudFlare
		email=$EmailCloudFlare

		################### Cho ra full thông tin lan dau tien:
		fullrawinfo=`curl --silent -X GET "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules?match=all" \
		     -H "X-Auth-Email: $email" \
		     -H "X-Auth-Key: $apikey" \
		     -H "Content-Type: application/json"`
		fullinfo=`echo "$fullrawinfo"|jq .`

		################### Cho ra tổng số rule lau dau tiên:
		numberrule=`echo "$fullinfo"| grep "total_count"|awk {'print $2'}`
		#echo "Tong rule la: $numberrule"
		so_rule_cf_ban_dau_co=$numberrule



		lapmaimai='lapmaimai';
		donglon=1
		while [ $lapmaimai = 'lapmaimai' ]
		do 

			################### Cho ra full thông tin khac nhau trong moi vong lap lớn:



			cat $file_chua_ip_log | grep 444 |awk {'print $1'} |awk '!x[$0]++' > $file_chua_ip_tam;

			cat $file_chua_ip_tam > $file_chua_ip_please_block;

			phat_hien_ip_moi=`cat $file_chua_ip_please_block|wc -l`
			if [ "$phat_hien_ip_moi" != "0" ] ; then
				
				ten_file_chua_list=$file_chua_ip_please_block
				echo "`cat $ten_file_chua_list | grep .`" > $ten_file_chua_list
				so_dong_file_chua_list=`cat $ten_file_chua_list | grep . | wc -l`
				################### Xoa toan bo ID Rules:

				dong=1
				while [ $dong -le $so_dong_file_chua_list ]
				do

				################### Xóa id rule hiện tại:
					thoigiantre=$((so_dong_file_chua_list/Time+1))
					delaytime=$(( $RANDOM % $thoigiantre )) # random từ 1 tới sodong/thoigianlap
					ipcaptcha_hientai=$(awk " NR == $dong " $ten_file_chua_list)

					(sleep $delaytime; curl -sSX POST "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules" \
										-H "X-Auth-Email: $email" \
										-H "X-Auth-Key: $apikey" \
										-H "Content-Type: application/json" \
										--data "{\"mode\":\"challenge\",\"configuration\":{\"target\":\"ip\",\"value\":\"$ipcaptcha_hientai\"},\"notes\":\"Captcha by vDDoS Proxy Protection\"}" >/dev/null 2>&1 & )&

					dong=$((dong + 1))
				done
			fi


			echo > $file_chua_ip_log; # Xoa file goc chua log de ghi IP moi
			sleep $Time;
			# Get thong tin de bao cao:
			fullrawinfo=`curl --silent -X GET "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules?match=all" \
			     -H "X-Auth-Email: $email" \
			     -H "X-Auth-Key: $apikey" \
			     -H "Content-Type: application/json"`
			fullinfo=`echo "$fullrawinfo"|jq .`
			numberrule=`echo "$fullinfo"| grep "total_count"|awk {'print $2'}`
			tong_so_rule_cf_hien_co=$numberrule
			tong_so_rule_cf_da_them_duoc=$((tong_so_rule_cf_hien_co-so_rule_cf_ban_dau_co))

			donglon=$((donglon + 1))
			clear
			echo '
			Scan '$donglon' Times:

		Detect new IP Address to CAPTCHA: '$phat_hien_ip_moi' IP Address
		Total CAPTCHA: '$tong_so_rule_cf_da_them_duoc' IP Address
			'
			lapmaimai='lapmaimai';
		done
	fi
	fi
fi




############# Nếu chọn 3. Enable Monitor-vDDoS-logs-and-Block Mode
if [ "$vDDoSLayer4Mode" = "3" ] ; then
	clear
	echo 'Please Go to CloudFlare.com and register an account:
	'
	echo -n 'Enter Your CloudFlare USERNAME [Ex: somebody@your-domain.com]: '
	read EmailCloudFlare
	echo -n 'Enter Your CloudFlare Global API-KEY [Ex: s0methin9key******]: '
	read APIKEYCloudFlare
	echo -n 'Enter Your CloudFlare ZONE-ID [Ex: s0methin9id**************]: '
	read ZONEKEYCloudFlare
	echo -n 'Enter Your Website you want to monitor [Ex: your-domain.com]: '
	read DomainName

	if [ "$EmailCloudFlare" = "" ] || [ "$APIKEYCloudFlare" = "" ] || [ "$ZONEKEYCloudFlare" = "" ] || [ "$DomainName" = "" ]; then
		echo 'ERROR! Please Try Again!
		'
		echo -n 'Press Enter to Back:'
		read Enter
		/usr/bin/vddos-layer4
	fi

	file_chua_ip_log="/var/log/vddos/444.log"
	if [  ! -f $file_chua_ip_log ]; then
		echo 'ERROR! File '$file_chua_ip_log' not found!
		'
		echo -n 'Press Enter to Back:'
		read Enter
		/usr/bin/vddos-layer4
	fi
	echo '
Time between to loops scan IP: 
	5 (5 second) - be careful when using
	10 (10 second)
	30 (30 second) - recommend
	60 (60 second) 
	'
	echo -n 'Enter Your choose [default 30]: '
	read Time
	if [ "$Time" = "" ] ; then
		Time=30
	fi
	echo '
Prefix IP Range to Block: 
	no (block exactly IP Attacker x.x.x.x) - if your server under attack by ~ 1000 IP Bots
	24 (block IP range Attacker x.x.x.x/24) - if your server under attack by ~ 65000 IP Bots
	16 (block IP range Attacker x.x.x.x/16) - be careful when using
	'
	echo -n 'Enter Your choose [default no]: '
	read Prefix
	mkdir -p /vddos/layer4-mapping/cf/$DomainName/block/
	file_chua_ip_log="/var/log/vddos/444.log"
	file_chua_ip_cu="/vddos/layer4-mapping/cf/$DomainName/block/Exist-Blocked.txt"
	file_chua_ip_tam="/vddos/layer4-mapping/cf/$DomainName/block/TMP.txt"
	file_chua_ip_please_block="/vddos/layer4-mapping/cf/$DomainName/block/Please-Block-This-IP.txt"

	echo > $file_chua_ip_log
	echo > $file_chua_ip_cu
	echo > $file_chua_ip_tam
	echo > $file_chua_ip_please_block

	if [ "$Prefix" = "16" ] ; then
		Prefix=16

		apikey=$APIKEYCloudFlare
		zone=$ZONEKEYCloudFlare
		email=$EmailCloudFlare

		################### Cho ra full thông tin lan dau tien:
		fullrawinfo=`curl --silent -X GET "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules?match=all" \
		     -H "X-Auth-Email: $email" \
		     -H "X-Auth-Key: $apikey" \
		     -H "Content-Type: application/json"`
		fullinfo=`echo "$fullrawinfo"|jq .`

		################### Cho ra tổng số rule lau dau tiên:
		numberrule=`echo "$fullinfo"| grep "total_count"|awk {'print $2'}`
		#echo "Tong rule la: $numberrule"
		so_rule_cf_ban_dau_co=$numberrule



		lapmaimai='lapmaimai';
		donglon=1
		while [ $lapmaimai = 'lapmaimai' ]
		do 





			cat $file_chua_ip_log | grep 444 |awk {'print $1'} | tr . " "| awk '{print $1"."$2"."0"."0"/"'$Prefix'}' |awk '!x[$0]++' > $file_chua_ip_tam;

			cat $file_chua_ip_tam > $file_chua_ip_please_block;

			phat_hien_ip_moi=`cat $file_chua_ip_please_block|wc -l`
			if [ "$phat_hien_ip_moi" != "0" ] ; then
				
				ten_file_chua_list=$file_chua_ip_please_block
				echo "`cat $ten_file_chua_list | grep .`" > $ten_file_chua_list
				so_dong_file_chua_list=`cat $ten_file_chua_list | grep . | wc -l`
				################### Xoa toan bo ID Rules:

				dong=1
				while [ $dong -le $so_dong_file_chua_list ]
				do

				################### Xóa id rule hiện tại:
					thoigiantre=$((so_dong_file_chua_list/Time+1))
					delaytime=$(( $RANDOM % $thoigiantre )) # random từ 1 tới sodong/thoigianlap
					ipblock_hientai=$(awk " NR == $dong " $ten_file_chua_list)

					(sleep $delaytime; curl -sSX POST "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules" \
										-H "X-Auth-Email: $email" \
										-H "X-Auth-Key: $apikey" \
										-H "Content-Type: application/json" \
										--data "{\"mode\":\"block\",\"configuration\":{\"target\":\"ip_range\",\"value\":\"$ipblock_hientai\"},\"notes\":\"Block by vDDoS Proxy Protection\"}" >/dev/null 2>&1 & )&

					dong=$((dong + 1))
				done
			fi


			echo > $file_chua_ip_log; # Xoa file goc chua log de ghi IP moi
			sleep $Time;
			# Get thong tin de bao cao:
			fullrawinfo=`curl --silent -X GET "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules?match=all" \
			     -H "X-Auth-Email: $email" \
			     -H "X-Auth-Key: $apikey" \
			     -H "Content-Type: application/json"`
			fullinfo=`echo "$fullrawinfo"|jq .`
			numberrule=`echo "$fullinfo"| grep "total_count"|awk {'print $2'}`
			tong_so_rule_cf_hien_co=$numberrule
			tong_so_rule_cf_da_them_duoc=$((tong_so_rule_cf_hien_co-so_rule_cf_ban_dau_co))

			donglon=$((donglon + 1))
			clear
			echo '
			Scan '$donglon' Times:

		Detect new IP Range to BLOCK: '$phat_hien_ip_moi' IP Range /'$Prefix'
		Total BLOCK: '$tong_so_rule_cf_da_them_duoc' IP Range
			'
			lapmaimai='lapmaimai';
		done

	else
	if [ "$Prefix" = "24" ] ; then
		Prefix=24
		apikey=$APIKEYCloudFlare
		zone=$ZONEKEYCloudFlare
		email=$EmailCloudFlare

		################### Cho ra full thông tin lan dau tien:
		fullrawinfo=`curl --silent -X GET "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules?match=all" \
		     -H "X-Auth-Email: $email" \
		     -H "X-Auth-Key: $apikey" \
		     -H "Content-Type: application/json"`
		fullinfo=`echo "$fullrawinfo"|jq .`

		################### Cho ra tổng số rule lau dau tiên:
		numberrule=`echo "$fullinfo"| grep "total_count"|awk {'print $2'}`
		#echo "Tong rule la: $numberrule"
		so_rule_cf_ban_dau_co=$numberrule



		lapmaimai='lapmaimai';
		donglon=1
		while [ $lapmaimai = 'lapmaimai' ]
		do 

			



			cat $file_chua_ip_log | grep 444 |awk {'print $1'} | tr . " "| awk '{print $1"."$2"."$3"."0"/"'$Prefix'}' |awk '!x[$0]++' > $file_chua_ip_tam;

			cat $file_chua_ip_tam > $file_chua_ip_please_block;

			phat_hien_ip_moi=`cat $file_chua_ip_please_block|wc -l`
			if [ "$phat_hien_ip_moi" != "0" ] ; then
				
				ten_file_chua_list=$file_chua_ip_please_block
				echo "`cat $ten_file_chua_list | grep .`" > $ten_file_chua_list
				so_dong_file_chua_list=`cat $ten_file_chua_list | grep . | wc -l`
				################### Xoa toan bo ID Rules:

				dong=1
				while [ $dong -le $so_dong_file_chua_list ]
				do

				################### Xóa id rule hiện tại:
					thoigiantre=$((so_dong_file_chua_list/Time+1))
					delaytime=$(( $RANDOM % $thoigiantre )) # random từ 1 tới sodong/thoigianlap
					ipblock_hientai=$(awk " NR == $dong " $ten_file_chua_list)

					(sleep $delaytime; curl -sSX POST "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules" \
										-H "X-Auth-Email: $email" \
										-H "X-Auth-Key: $apikey" \
										-H "Content-Type: application/json" \
										--data "{\"mode\":\"block\",\"configuration\":{\"target\":\"ip_range\",\"value\":\"$ipblock_hientai\"},\"notes\":\"Block by vDDoS Proxy Protection\"}" >/dev/null 2>&1 & )&

					dong=$((dong + 1))
				done
			fi


			echo > $file_chua_ip_log; # Xoa file goc chua log de ghi IP moi
			sleep $Time;
			# Get thong tin de bao cao:
			fullrawinfo=`curl --silent -X GET "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules?match=all" \
			     -H "X-Auth-Email: $email" \
			     -H "X-Auth-Key: $apikey" \
			     -H "Content-Type: application/json"`
			fullinfo=`echo "$fullrawinfo"|jq .`
			numberrule=`echo "$fullinfo"| grep "total_count"|awk {'print $2'}`
			tong_so_rule_cf_hien_co=$numberrule
			tong_so_rule_cf_da_them_duoc=$((tong_so_rule_cf_hien_co-so_rule_cf_ban_dau_co))

			donglon=$((donglon + 1))
			clear
			echo '
			Scan '$donglon' Times:

		Detect new IP Range to BLOCK: '$phat_hien_ip_moi' IP Range /'$Prefix'
		Total BLOCK: '$tong_so_rule_cf_da_them_duoc' IP Range
			'
			lapmaimai='lapmaimai';
		done

	else
		Prefix=1

		apikey=$APIKEYCloudFlare
		zone=$ZONEKEYCloudFlare
		email=$EmailCloudFlare

		################### Cho ra full thông tin lan dau tien:
		fullrawinfo=`curl --silent -X GET "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules?match=all" \
		     -H "X-Auth-Email: $email" \
		     -H "X-Auth-Key: $apikey" \
		     -H "Content-Type: application/json"`
		fullinfo=`echo "$fullrawinfo"|jq .`

		################### Cho ra tổng số rule lau dau tiên:
		numberrule=`echo "$fullinfo"| grep "total_count"|awk {'print $2'}`
		#echo "Tong rule la: $numberrule"
		so_rule_cf_ban_dau_co=$numberrule



		lapmaimai='lapmaimai';
		donglon=1
		while [ $lapmaimai = 'lapmaimai' ]
		do 

			



			cat $file_chua_ip_log | grep 444 |awk {'print $1'} |awk '!x[$0]++' > $file_chua_ip_tam;

			cat $file_chua_ip_tam > $file_chua_ip_please_block;

			phat_hien_ip_moi=`cat $file_chua_ip_please_block|wc -l`
			if [ "$phat_hien_ip_moi" != "0" ] ; then
				
				ten_file_chua_list=$file_chua_ip_please_block
				echo "`cat $ten_file_chua_list | grep .`" > $ten_file_chua_list
				so_dong_file_chua_list=`cat $ten_file_chua_list | grep . | wc -l`
				################### Xoa toan bo ID Rules:

				dong=1
				while [ $dong -le $so_dong_file_chua_list ]
				do

				################### Xóa id rule hiện tại:
					thoigiantre=$((so_dong_file_chua_list/Time+1))
					delaytime=$(( $RANDOM % $thoigiantre )) # random từ 1 tới sodong/thoigianlap
					ipblock_hientai=$(awk " NR == $dong " $ten_file_chua_list)

					(sleep $delaytime; curl -sSX POST "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules" \
										-H "X-Auth-Email: $email" \
										-H "X-Auth-Key: $apikey" \
										-H "Content-Type: application/json" \
										--data "{\"mode\":\"block\",\"configuration\":{\"target\":\"ip\",\"value\":\"$ipblock_hientai\"},\"notes\":\"Block by vDDoS Proxy Protection\"}" >/dev/null 2>&1 & )&

					dong=$((dong + 1))
				done
			fi


			echo > $file_chua_ip_log; # Xoa file goc chua log de ghi IP moi
			sleep $Time;
			# Get thong tin de bao cao:
			fullrawinfo=`curl --silent -X GET "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules?match=all" \
			     -H "X-Auth-Email: $email" \
			     -H "X-Auth-Key: $apikey" \
			     -H "Content-Type: application/json"`
			fullinfo=`echo "$fullrawinfo"|jq .`
			numberrule=`echo "$fullinfo"| grep "total_count"|awk {'print $2'}`
			tong_so_rule_cf_hien_co=$numberrule
			tong_so_rule_cf_da_them_duoc=$((tong_so_rule_cf_hien_co-so_rule_cf_ban_dau_co))

			donglon=$((donglon + 1))
			clear
			echo '
			Scan '$donglon' Times:

		Detect new IP Address to BLOCK: '$phat_hien_ip_moi' IP Address
		Total BLOCK: '$tong_so_rule_cf_da_them_duoc' IP Address
			'
			lapmaimai='lapmaimai';
		done
	fi
	fi
fi


############# Nếu chọn 4. Remove all rules exist on CloudFlare Firewall
if [ "$vDDoSLayer4Mode" = "4" ] ; then
	clear
	echo 'Remove all rules exist on CloudFlare Firewall:'
	echo 'Please Go to CloudFlare.com and get account info:
	'
	echo -n 'Enter Your CloudFlare USERNAME [somebody@your-domain.com]: '
	read EmailCloudFlare
	echo -n 'Enter Your CloudFlare Global API-KEY [s0methin9key******]: '
	read APIKEYCloudFlare
	echo -n 'Enter Your CloudFlare ZONE-ID [s0methin9id**************]: '
	read ZONEKEYCloudFlare


	apikey=$APIKEYCloudFlare
	zone=$ZONEKEYCloudFlare
	email=$EmailCloudFlare

	################### Cho ra full thông tin lan dau tien:
	fullrawinfo=`curl --silent -X GET "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules?match=all" \
	     -H "X-Auth-Email: $email" \
	     -H "X-Auth-Key: $apikey" \
	     -H "Content-Type: application/json"`
	fullinfo=`echo "$fullrawinfo"|jq .`

	################### Cho ra tổng số rule lau dau tiên:
	numberrule=`echo "$fullinfo"| grep "total_count"|awk {'print $2'}`
	#echo "Tong rule la: $numberrule"

	################### Curl gửi Xoa toan bo ID Rules:

	mkdir -p /vddos/layer4-mapping/vddos-layer4-mapping-cf-remove-all-rule
	ten_file_chua_list='/vddos/layer4-mapping/vddos-layer4-mapping-cf-remove-all-rule/CF-idrulelist.txt'
	rulebandau=$numberrule
	so_lan_vong_lap_lon=0
	donglon=1
	while [ $numberrule -gt $so_lan_vong_lap_lon ]
	do

		################### Cho ra full thông tin khac nhau trong moi vong lap lớn:

		fullrawinfo=`curl --silent -X GET "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules?match=all" \
		     -H "X-Auth-Email: $email" \
		     -H "X-Auth-Key: $apikey" \
		     -H "Content-Type: application/json"`
		fullinfo=`echo "$fullrawinfo"|jq .`
		################### Cho ra full ID Rules khac nhau trong moi vong lap lớn:
		idrulelist=`echo "$fullinfo" | grep '"id":' |sed "/.*$zone.*/d" | awk {'print $2'}| tr -d ','|tr -d '"'`
		#echo "Danh sach ID la:
		#$idrulelist"
		echo "$idrulelist" > $ten_file_chua_list
		echo "`cat $ten_file_chua_list | grep .`" > $ten_file_chua_list
		so_dong_file_chua_list=`cat $ten_file_chua_list | grep . | wc -l`
		################### Xoa toan bo ID Rules:



		dong=1
		while [ $dong -le $so_dong_file_chua_list ]
		do

		################### Xóa id rule hiện tại:
			delaytime=$(( $RANDOM % 9 ))
			idrulehientai=$(awk " NR == $dong " $ten_file_chua_list)

			(sleep $delaytime; curl --silent -X DELETE "https://api.cloudflare.com/client/v4/zones/$zone/firewall/access_rules/rules/$idrulehientai" \
					-H "X-Auth-Email: $email" \
					-H "X-Auth-Key: $apikey" \
					-H "Content-Type: application/json" >/dev/null 2>&1 &) &
			echo "Remove rule number $dong on page $donglon have id $idrulehientai"
			dong=$((dong + 1))
		done
	donglon=$((donglon + 1))
	sleep 5
	################### Cho ra tổng số rule hiện tại sau khi xóa:
	numberrule=`echo "$fullinfo"| grep "total_count"|awk {'print $2'}`
	# Nếu rule vẫn lớn hơn 0 thì lại tiếp tục lặp
	echo "     Removed: $((rulebandau-numberrule)) rule => Exist: $numberrule rule"
	done
	echo -n 'Press Enter to Back:'
	read Enter
	/usr/bin/vddos-layer4
fi

############# Nếu chọn 5. Enable Monitor-vDDoS-logs-and-Block Mode CSF
if [ "$vDDoSLayer4Mode" = "5" ] ; then
	if [ ! -f /etc/csf/csf.deny ]; then
		echo 'ERROR! Please install CSF & Try Again!
	'
		exit 0
	fi
	if [ ! -f /var/log/vddos/444.log ]; then
		echo 'ERROR! File /var/log/vddos/444.log not found!
	'
		exit 0
	fi


	clear
	echo 'Enable Monitor-vDDoS-logs-and-Block Mode CSF:
	'
	echo '
Time between to loops scan IP: 
	5 (5 second) - be careful when using
	10 (10 second)
	30 (30 second) - recommend
	60 (60 second) 
	'
	echo -n 'Enter Your choose [default 30]: '
	read Time
	if [ "$Time" = "" ] ; then
		Time=30
	fi
	echo '
Prefix IP Range to block: 
	no (block exactly IP Attacker x.x.x.x) - if your server under attack by ~ 1000 IP Bots
	24 (block range IP Attacker x.x.x.x/24) - if your server under attack by ~ 65000 IP Bots
	16 (block range IP Attacker x.x.x.x/16) - be careful when using
	'
	echo -n 'Enter Your choose [default no]: '
	read Prefix
	mkdir -p /vddos/layer4-mapping/csf/block/
	file_chua_ip_log='/var/log/vddos/444.log'
	file_chua_ip_cu='/vddos/layer4-mapping/csf/block/Exist-Blocked.txt'
	file_chua_ip_tam='/vddos/layer4-mapping/csf/block/TMP.txt'
	file_chua_ip_please_block='/vddos/layer4-mapping/csf/block/Please-Block-This-IP.txt'
	file_chua_ip_csf_deny='/etc/csf/csf.deny'
	echo > $file_chua_ip_log
	echo > $file_chua_ip_cu
	echo > $file_chua_ip_tam
	echo > $file_chua_ip_please_block
	echo > $file_chua_ip_csf_deny
	if [ "$Prefix" = "16" ] ; then
		Prefix=16
		lapmaimai='lapmaimai';
		dong=1
		while [ $lapmaimai = 'lapmaimai' ]
		do 
			
			cat $file_chua_ip_log | grep 444 |awk {'print $1'} | tr . " "| awk '{print $1"."$2"."0"."0"/"'$Prefix'}' |awk '!x[$0]++' > $file_chua_ip_tam;
			echo > $file_chua_ip_log; # Xoa file goc chua log de ghi IP moi
			cat $file_chua_ip_cu >> $file_chua_ip_tam; # bỏ file cũ thêm vào dưới file tạm
			phat_hien_ip_cu=`cat $file_chua_ip_cu|wc -l` # tính số IP file cũ thêm vào dưới file tạm
			cat $file_chua_ip_tam |awk '!x[$0]++' > $file_chua_ip_please_block; # Lọc IP mới + cũ vào file cần block
			phat_hien_tong_ip_please_block=`cat $file_chua_ip_please_block|wc -l` # tổng số Ip mới + cũ
			phat_hien_ip_moi=$((phat_hien_tong_ip_please_block-phat_hien_ip_cu)) # tổng ip mới sẽ bằng tổng ip mới + cũ trừ đi số ip cũ
			cat $file_chua_ip_please_block > $file_chua_ip_csf_deny;
			phat_hien_ip_tong=`cat $file_chua_ip_csf_deny|wc -l`
			cat $file_chua_ip_csf_deny > $file_chua_ip_cu;
			if [ "$phat_hien_ip_moi" != "0" ] ; then # Tổng ip mới nếu khác 0 thì sẽ restart CSF
				/usr/sbin/csf -r >/dev/null 2>&1;
			fi
			dong=$((dong + 1))
			clear
			echo '
			Scan '$dong' Times:

		Detect new IP Range to DROP: '$phat_hien_ip_moi' IP Range /'$Prefix'
		Old Block: '$phat_hien_ip_cu' IP Range
		Total Block: '$phat_hien_ip_tong' IP Range
			'
			sleep $Time;
		done
	else

	if [ "$Prefix" = "24" ] ; then
		Prefix=24
		lapmaimai='lapmaimai';
		dong=1
		while [ $lapmaimai = 'lapmaimai' ]
		do 
			
			cat $file_chua_ip_log | grep 444 |awk {'print $1'} | tr . " "| awk '{print $1"."$2"."$3"."0"/"'$Prefix'}' |awk '!x[$0]++' > $file_chua_ip_tam;
			echo > $file_chua_ip_log; # Xoa file goc chua log de ghi IP moi
			cat $file_chua_ip_cu >> $file_chua_ip_tam; # bỏ file cũ thêm vào dưới file tạm
			phat_hien_ip_cu=`cat $file_chua_ip_cu|wc -l` # tính số IP file cũ thêm vào dưới file tạm
			cat $file_chua_ip_tam |awk '!x[$0]++' > $file_chua_ip_please_block; # Lọc IP mới + cũ vào file cần block
			phat_hien_tong_ip_please_block=`cat $file_chua_ip_please_block|wc -l` # tổng số Ip mới + cũ
			phat_hien_ip_moi=$((phat_hien_tong_ip_please_block-phat_hien_ip_cu)) # tổng ip mới sẽ bằng tổng ip mới + cũ trừ đi số ip cũ
			cat $file_chua_ip_please_block > $file_chua_ip_csf_deny;
			phat_hien_ip_tong=`cat $file_chua_ip_csf_deny|wc -l`
			cat $file_chua_ip_csf_deny > $file_chua_ip_cu;
			if [ "$phat_hien_ip_moi" != "0" ] ; then # Tổng ip mới nếu khác 0 thì sẽ restart CSF
				/usr/sbin/csf -r >/dev/null 2>&1;
			fi
			dong=$((dong + 1))
			clear
			echo '
			Scan '$dong' Times:

		Detect new IP Range to DROP: '$phat_hien_ip_moi' IP Range /'$Prefix'
		Old Block: '$phat_hien_ip_cu' IP Range
		Total Block: '$phat_hien_ip_tong' IP Range
			'
			sleep $Time;
		done
	else

		Prefix=1
		lapmaimai='lapmaimai';
		dong=1
		while [ $lapmaimai = 'lapmaimai' ]
		do 
			
			cat $file_chua_ip_log | grep 444 |awk {'print $1'} |awk '!x[$0]++' > $file_chua_ip_tam;
			echo > $file_chua_ip_log; # Xoa file goc chua log de ghi IP moi
			cat $file_chua_ip_cu >> $file_chua_ip_tam; # bỏ file cũ thêm vào dưới file tạm
			phat_hien_ip_cu=`cat $file_chua_ip_cu|wc -l` # tính số IP file cũ thêm vào dưới file tạm
			cat $file_chua_ip_tam |awk '!x[$0]++' > $file_chua_ip_please_block; # Lọc IP mới + cũ vào file cần block
			phat_hien_tong_ip_please_block=`cat $file_chua_ip_please_block|wc -l` # tổng số Ip mới + cũ
			phat_hien_ip_moi=$((phat_hien_tong_ip_please_block-phat_hien_ip_cu)) # tổng ip mới sẽ bằng tổng ip mới + cũ trừ đi số ip cũ
			cat $file_chua_ip_please_block > $file_chua_ip_csf_deny;
			phat_hien_ip_tong=`cat $file_chua_ip_csf_deny|wc -l`
			cat $file_chua_ip_csf_deny > $file_chua_ip_cu;
			if [ "$phat_hien_ip_moi" != "0" ] ; then # Tổng ip mới nếu khác 0 thì sẽ restart CSF
				/usr/sbin/csf -r >/dev/null 2>&1;
			fi
			dong=$((dong + 1))
			clear
			echo '
			Scan '$dong' Times:

		Detect new IP to DROP: '$phat_hien_ip_moi' IP Address
		Old Block: '$phat_hien_ip_cu' IP Address
		Total Block: '$phat_hien_ip_tong' IP Address
			'
			sleep $Time;
		done
	fi
	fi

	echo -n 'Press Enter to Back:'
	read Enter
	/usr/bin/vddos-layer4

fi


############# Nếu chọn 6. Remove all rules exist on CSF
if [ "$vDDoSLayer4Mode" = "6" ] ; then
	if [ ! -f /etc/csf/csf.deny ]; then
		echo 'ERROR! Please install CSF & Try Again!
	'
		exit 0
	fi
	clear
	echo 'Remove all rules exist on CSF:
	'
	sodong=`cat /etc/csf/csf.deny | grep . | wc -l`
	echo > /etc/csf/csf.deny
	/usr/sbin/csf -r >/dev/null 2>&1
	/usr/sbin/csf -q >/dev/null 2>&1
	service lfd restart >/dev/null 2>&1
	/usr/sbin/csf -tf >/dev/null 2>&1
	/usr/sbin/csf -df >/dev/null 2>&1
	echo 'Removed all '$sodong' rule in csf.deny!
	'
	echo -n 'Press Enter to Back:'
	read Enter
	/usr/bin/vddos-layer4
fi

############# Nếu chọn 7. End All Process (Kill all Process Mode Running)
if [ "$vDDoSLayer4Mode" = "7" ] ; then
	echo 'End All vDDoS Layer 4 Process Suscess!'
	pkill -f vddos-layer4 >/dev/null 2>&1
	exit 0
fi

############# Nếu chọn 8 hoặc không phải 1 đến 8 Exit
if [ "$vDDoSLayer4Mode" = "" ] ; then
	vDDoSLayer4Mode=8
fi

if [ "$vDDoSLayer4Mode" = "8" ] ; then
	echo 'Exit!'
	exit 0
fi
