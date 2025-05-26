#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#===============================================================================
#	О, ЗДАРОВА, А ТЫ НАХУЯ В ИСХОДНИКИ ЗАЛЕЗ? Я ЖЕ ТЕБЯ ПО АЙПИ ВЫЧИСЛЮ!
#   НУ ЛАДНО, ПИЗДИЙ, ПИЗДИЙ КОД... ВСЕ ЧТО ТЕБЕ НУЖНО ПРЯМО ПОД ЭТИМ ТЕКСТОМ...
#===============================================================================


#==================================================================================================
# ========================== ПЕРЕМЕННЫЕ ===========================================================
sh_ver="3.0"
filepath=$(cd "$(dirname "$0")"; pwd)
file=$(echo -e "${filepath}"|awk -F "$0" '{print $1}')
ssr_folder="/usr/local/shadowsocksr"
config_file="${ssr_folder}/config.json"
config_user_file="${ssr_folder}/user-config.json"
config_user_api_file="${ssr_folder}/userapiconfig.py"
config_user_mudb_file="${ssr_folder}/mudb.json"
ssr_log_file="${ssr_folder}/ssserver.log"
Libsodiumr_file="/usr/local/lib/libsodium.so"
Libsodiumr_ver_backup="1.0.15"
Server_Speeder_file="/serverspeeder/bin/serverSpeeder.sh"
LotServer_file="/appex/bin/serverSpeeder.sh"
BBR_file="${file}/bbr.sh"
jq_file="${ssr_folder}/jq"
tgid="-1001530603430"  # ID чата для автобэкапа (Необходим доступ к сообщениям)
tg2id="-1001530603430" # ID чата диллерской группы для отправки ключей
admls="5368937600"	   # ID Админа
bot_api="5579992688:AAHikz946E3rrygOmHk0SftNZswV5BUDEsA" # Токен бота 
backup_serv_id="$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')" # Получение домена сервера из конфига
Deal1="lemon"
Deal2="fon"
Deal3="lim"
Deal4="bean"
Deal5="leon"
Green="\033[32m" && Red="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Purple="\033[35m" && Yellow="\033[33m" && Font_default="\033[0m" && Blue='\033[34m' && Ocean='\033[36m'
Info="${Green}[Информация]${Font_default}"
Error="${Red}[Ошибка]${Font_default}"
Tip="${Green}[Заметка]${Font_default}"
Separator_1="${Purple}|————————————————————————————————————|${Font_default}"
#==================================================================================================

#===================================== ВСЕ ЧТО БЫЛО ДОБАВЛЕНО =====================================

Requirements_install(){
	sudo apt-get --yes install curl
	sudo apt-get --yes install jq
	sudo apt-get --yes install zip
	sudo apt-get --yes install net-tools
	sudo apt-get --yes install at
	sudo systemctl enable --now atd
}

Upload_DB(){
	backupURL="$(curl -F "file=@/usr/local/shadowsocksr/mudb.json" https://file.io | jq '.link')"
	echo -e "
${Purple}———————————————————————————————————————————————————————————————
${Red} $backupURL ${Font_default}
${Purple}———————————————————————————————————————————————————————————————
${Red}Baza dannylary buluda goýuldy. Aşaky ssylkany kopyalaň.
${Purple}———————————————————————————————————————————————————————————————
"
#curl -s -X POST https://api.telegram.org/bot1920143861:AAG-4kMzOtckxsvhbuVjcKKHcko8ueeJJa0/sendMessage -d chat_id=1492493380 -d text="$backupURL"
}

Download_DB(){
	echo -e "
———————————————
${Red}Ssylkany goýuň${Font_default}
———————————————
"
	read -p "|Ssylka:|  " dburl
	curl -o /usr/local/shadowsocksr/mudb.json $dburl
	echo -e "
${Purple}————————————————————————————————————————————————
${Info} ${Red}Maglumat bazasy ýüklendi${Font_default}
${Purple}————————————————————————————————————————————————
"
	Restart_SSR
	echo -e "${Tip} SSR öçürüp yakyldy!"
}

Autobak_cron_start(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssr.sh/d" "$file/crontab.bak"
	echo -e "\n${Crontab_time} bash ssr.sh autobak" >> "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssr.sh")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} Awto_Bekup ${Red}işledilmedi ${Font_default}" && exit 1
	else
		echo -e "${Info} Awto_Bekup ${Green}işledildi ${Font_default}"
		curl -s -X POST https://api.telegram.org/bot"$bot_api"/sendMessage -d chat_id="$tgid" -d text="Shadowsocks Awto-Bekupy $backup_serv_id işledildi"
	fi
}

Autobak_cron_stop(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssr.sh/d" "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssr.sh")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} Awto-Bekupy öçürüp bilmedik!" && exit 1
	else
		echo -e "${Info} Awto-Bekup ${Green} üstünlikli ${Font_default} öçürildi!"
		curl -s -X POST https://api.telegram.org/bot"$bot_api"/sendMessage -d chat_id="$tgid" -d text="Shadowsocks Awto-Bekupy $backup_serv_id öçürildi"
	fi
}

Autobak_cron_modify(){
	Set_crontab
	Autobak_cron_stop
	Autobak_cron_start
}

Autobak(){
	backupURL="$(curl -F "file=@/usr/local/shadowsocksr/mudb.json" https://file.io | jq '.link')"
	curl -s -X POST https://api.telegram.org/bot"$bot_api"/sendMessage -d chat_id="$tgid" -d text="Shadowsocks serverynyň bekupy $backup_serv_id %0A Дата: $(date) %0A Bekup ssylkasy: $backupURL "
}

AutobakMenu(){
	SSR_installation_status
	echo && echo -e "
${Purple}|————————————————————————————————————|${Font_default} 
${Purple}|${Font_default}${Purple}———————————${Font_default} Näme edeli? ${Purple}————————————${Font_default}${Purple}|${Font_default}
${Purple}|1.${Font_default} ${Red} Awto-Bekupy işlet  ${Font_default}             ${Purple}|${Font_default}
${Purple}|2.${Font_default} ${Red} Awto-Bekupy öçür ${Font_default}               ${Purple}|${Font_default}
${Purple}|3.${Font_default} ${Red} Awto-Bekup wagtyny düzmek${Font_default}       ${Purple}|${Font_default}
${Purple}|————————————————————————————————————|${Font_default}" && echo
	read -e -p "(По умолчанию: Ýatyrmak):" cronbak_modify
	[[ -z "${cronbak_modify}" ]] && echo "Ýatyrmak..." && exit 1
	if [[ ${cronbak_modify} == "1" ]]; then
		Set_crontab
		Autobak_cron_start
	elif [[ ${cronbak_modify} == "2" ]]; then
		Autobak_cron_stop
	elif [[ ${cronbak_modify} == "3" ]]; then
		Autobak_cron_modify
	else
		echo -e "${Error} Dogry sany saýlaň (1-5)" && exit 1
	fi
}

DomainChange(){
	SSR_installation_status
	user_info=$(python mujson_mgr.py -l)
	usrport=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
	echo -e "
${Purple}|———————————————————————————————————————————————————|${Font_default}
${Purple}|${Red}Telegram üçin täze açarlary çykaryp bermek? [y/N]${Font_default}  ${Purple}|${Font_default}
${Purple}|———————————————————————————————————————————————————|${Font_default}" && echo
		read -e -p "(По умолчанию: n):" yn
		[[ -z ${yn} ]] && yn="n"
		if [[ ${yn} == [Yy] ]]; then
	curl -s -X POST https://api.telegram.org/bot"$bot_api"/sendMessage -d chat_id="$admls" -d parse_mode=Markdown -d text="Domen bloklanandan soň dikeltmek işleri başladyldy" >> curl.tmp
	for user_port in $usrport
	do
	Get_user_port=$user_port
	user_info_get=$(python mujson_mgr.py -l -p "${Get_user_port}")
	user_name=$(echo "${user_info_get}"|grep -w "user :"|awk -F "user : " '{print $NF}')
	port=$(echo "${user_info_get}"|grep -w "port :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	password=$(echo "${user_info_get}"|grep -w "passwd :"|awk -F "passwd : " '{print $NF}')
	method=$(echo "${user_info_get}"|grep -w "method :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol=$(echo "${user_info_get}"|grep -w "protocol :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol_param=$(echo "${user_info_get}"|grep -w "protocol_param :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	obfs=$(echo "${user_info_get}"|grep -w "obfs :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	ip=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
	ss_ssr_determine
	curl -s -X POST https://api.telegram.org/bot"$bot_api"/sendMessage -d chat_id="$admls" -d parse_mode=Markdown -d text="Shadowsocks açarlaryny dikeltmek %0A Сервер: $backup_serv_id %0A Nikneým: ${user_name} %0A Açar: ${tg_ss_link}" >> curl.tmp
	sleep 0.2
	done
	curl -s -X POST https://api.telegram.org/bot"$bot_api"/sendMessage -d chat_id="$admls" -d parse_mode=Markdown -d text="Üstünlikli dikeltdik!" >> curl.tmp
	rm -r curl.tmp
	echo -e "Açarlary paýladyk."
		else
			echo -e "${Red}Ýatyrmak..."
	fi
}

AutoDelUsrList(){
	cd "${ssr_folder}"
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	user_username=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
	[[ -z ${user_info} ]] && echo -e "${Error} Ulanyjy tapylmady !" && exit 1
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_username=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		user_list_all=${user_list_all}"Ulanyjy: ${Red} "${user_username}"${Font_default} Port: ${Yellow}"${user_port}"${Font_default}\n"
	done
	echo -e "${user_list_all}"
}
AutoDelMake(){
	howtomake=$howtomakedel
	if [[ "$howtomake" == "addport" ]]; then
		user_info_get=$(python mujson_mgr.py -l -p "${ssr_port}")
		user_name=$(echo "${user_info_get}"|grep -w "user :"|awk -F "user : " '{print $NF}')
		echo -e "${Red}Açary näçe günden pozmaly? ${Font_default}"
		read -e -p deltime "günden soň " 
		at now +$deltime days <<ENDMARKER
cd /usr/local/shadowsocksr
python mujson_mgr.py -d -p "${port}"
iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
iptables-save > /etc/iptables.up.rules
ip6tables-save > /etc/ip6tables.up.rules
sed -i "/$port,/d" deldatabase.csv
curl -s -X POST https://api.telegram.org/bot"$bot_api"/sendMessage -d chat_id="$tg2id" -d text="Awto-Pozmak işleri geçirldi %0A Ulanyjy: ${user_name} %0A Port: ${port} %0A Server: ${backup_serv_id}" >> curl.tmp
rm -r curl.tmp
ENDMARKER
		cd "${ssr_folder}"
		deldate=$(date --date="$deltime days" +"%b %d %Y")
		echo "$port,$user_name,$deldate" >> "/usr/local/shadowsocksr/deldatabase.csv"
	else
		echo -e "${Red}Nastroýka etmek üçin ulanyjynyň portyny ýazyň${Font_default}"
		read -e -p "Port: " port
		user_info_get=$(python mujson_mgr.py -l -p "${port}")
		user_name=$(echo "${user_info_get}"|grep -w "user :"|awk -F "user : " '{print $NF}')
		echo -e "${Red}Näçe günden açary pozmaly? ${Font_default}"
		read -e -p deltime "günden soň " 
		at now +$deltime days <<ENDMARKER
cd /usr/local/shadowsocksr
python mujson_mgr.py -d -p "${port}"
iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
iptables-save > /etc/iptables.up.rules
ip6tables-save > /etc/ip6tables.up.rules
sed -i "/$port,/d" deldatabase.csv
curl -s -X POST https://api.telegram.org/bot"$bot_api"/sendMessage -d chat_id="$tg2id" -d text="Awto-Pozmak işleri geçirldi %0A Ulanyjy: ${user_name} %0A Port: ${port} %0A Server: ${backup_serv_id}" >> curl.tmp
rm -r curl.tmp
ENDMARKER
		cd "${ssr_folder}"
		deldate=$(date --date="$deltime days" +"%b %d %Y")
		echo "$port,$user_name,$deldate" >> "/usr/local/shadowsocksr/deldatabase.csv"
		echo -e "Автоудаление ключа ${port} настроено"
		curl -s -X POST https://api.telegram.org/bot"$bot_api"/sendMessage -d chat_id="$tg2id" -d text="Shadowsocks açarlarynyň awto pozulmagy düzüldi %0A Ulanyjy: ${user_name} %0A Port: ${port} %0A Server: ${backup_serv_id} %0A Pozulma senesi: ${deldate}" >> curl.tmp
		rm -r curl.tmp
	fi
}

AutoDelReload(){
	cd /usr/local/shadowsocksr
	ports=$(csvtool col 1 deldatabase.csv)
	for port in $ports
	do
	username=$(csvtool col 2 deldatabase.csv)
	deltime=$(csvtool col 3 deldatabase.csv)
	at $deltime <<ENDMARKER
cd /usr/local/shadowsocksr
python mujson_mgr.py -d -p "${port}"
iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
iptables-save > /etc/iptables.up.rules
ip6tables-save > /etc/ip6tables.up.rules
sed -i "/$port,/d" deldatabase.csv
curl -s -X POST https://api.telegram.org/bot"$bot_api"/sendMessage -d chat_id="$tg2id" -d text="Shadowsocks açarlarynyň awto pozulmagy düzüldi %0A Ulanyjy: ${user_name} %0A Port: ${port} %0A Server: ${backup_serv_id}" >> curl.tmp
rm -r curl.tmp
ENDMARKER
	done
	curl -s -X POST https://api.telegram.org/bot"$bot_api"/sendMessage -d chat_id="$tg2id" -d text="açarlaryp awto-pozulmagy bekupdan soň dikeldildi %0A Server: ${backup_serv_id}" >> curl.tmp
	rm -r curl.tmp
}

AutoDelCancel(){
echo -e "${Red}В разработке!${Font_default}" && exit 1
}

AutoDelCheck(){
	username="$(csvtool col 2 deldatabase.csv)"
	ports="$(csvtool col 1 deldatabase.csv)"
	deltime="$(csvtool col 3 deldatabase.csv)"
	for port in ports
	do
	echo -e "Ulanyjy: ${Ocean}${username} Port: ${Yellow}${ports} Pozulma senesi: ${Red}${deltime}${Font_default}"
	done
}

AutoDelMenu(){
	echo && echo -e "
${Purple}|——————————————————————————————————————————————————————|${Font_default} 
${Purple}|${Font_default}${Purple}—————————————————————————${Font_default} Näme edeli?${Purple} ——————————————————————|${Font_default}
${Purple}|1.${Font_default} ${Red} Ulanyjynyň pozulmasyny sazla                   ${Purple}|${Font_default}
${Purple}|2.${Font_default} ${Red} Ulanyjynyň awto pozulmagyny ýatyr (Düzülýär!)${Purple}|${Font_default}
${Purple}|3.${Font_default} ${Red} Ulanyjylaryň näçe gününiň galanyny görmek         ${Purple}|${Font_default}
${Purple}|——————————————————————————————————————————————————————|${Font_default}" && echo
	read -e -p "(По умолчанию: Ýatyrmak):" choice
	[[ -z "${choice}" ]] && echo "Ýatyrylýar..." && exit 1
	if [[ ${choice} == "1" ]]; then
		AutoDelUsrList
		AutoDelMake
	elif [[ ${choice} == "2" ]]; then
		AutoDelCancel
	elif [[ ${choice} == "3" ]]; then
		AutoDelCheck
	else
		echo -e "${Error} Dogry nomeri saýlaň (1-3)" && exit 1
	fi
}

DealersList(){
	echo -e "
${Purple}|————————————————————————————————————|${Font_default} 
${Purple}|${Font_default}${Purple}———————————${Font_default} Tag saýlaň ${Purple}———————————${Font_default}${Purple}|${Font_default}
${Purple}|1.${Font_default} ${Red}${Deal1}  ${Font_default}
${Purple}|2.${Font_default} ${Red}${Deal2} ${Font_default}
${Purple}|3.${Font_default} ${Red}${Deal3} ${Font_default}
${Purple}|4.${Font_default} ${Red}${Deal4} ${Font_default}
${Purple}|5.${Font_default} ${Red}${Deal5} ${Font_default}
${Purple}|6.${Font_default} ${Green}Tag-syz düz ${Font_default}
${Purple}|————————————————————————————————————|${Font_default}"
	read -e -p "Öz tag-ynyzy saýlaň (По умолчанию: Tag-syz): " adminacc
	[[ -z "${adminacc}" ]] && adminacc="6"
	if [[ ${adminacc} == "1" ]]; then
		admacc="$Deal1"
	elif [[ ${adminacc} == "2" ]]; then
		admacc="$Deal2"
	elif [[ ${adminacc} == "3" ]]; then
		admacc="$Deal3"
	elif [[ ${adminacc} == "4" ]]; then
		admacc="$Deal4"
	elif [[ ${adminacc} == "5" ]]; then
		admacc="$Deal5"
	elif [[ ${adminacc} == "6" ]]; then
		admacc=
	else
		admacc=
	fi
}

#===================================== КОНЕЦ ДОБАВЛЕННОГО =====================================
#===================================== ВСЕ СЛИЗАЛ? ============================================
check_root(){
	[[ $EUID != 0 ]] && echo -e "${Error} Skript root bilen işledilmedi. Ýazyň: ${Green_background_prefix} sudo su ${Font_default} We programma täzeden giriň." && exit 1
}
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
	bit=`uname -m`
}
check_pid(){
	PID=`ps -ef |grep -v grep | grep server.py |awk '{print $2}'`
}
check_crontab(){
	[[ ! -e "/usr/bin/crontab" ]] && echo -e "${Error} Отсутствует crontab: для установки на CentOS пропишите yum install crond -y , Debian/Ubuntu: apt-get install cron -y !" && exit 1
}
SSR_installation_status(){
	[[ ! -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR tapylmady!" && exit 1
}
Server_Speeder_installation_status(){
	[[ ! -e ${Server_Speeder_file} ]] && echo -e "${Error} Server Speeder gurnalmadyk !" && exit 1
}
LotServer_installation_status(){
	[[ ! -e ${LotServer_file} ]] && echo -e "${Error} LotServer gurnalmadyk !" && exit 1
}
BBR_installation_status(){
	if [[ ! -e ${BBR_file} ]]; then
		echo -e "${Error} BBR tapylmady, gurnap başladyk..."
		cd "${file}"
		if ! wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/bbr.sh; then
			echo -e "${Error} BBR-y gurnap bilmedik! !" && exit 1
		else
			echo -e "${Info} BBR-y gurnadyk !"
			chmod +x bbr.sh
		fi
	fi
}
# 设置 防火墙规则
Add_iptables(){
	if [[ ! -z "${ssr_port}" ]]; then
		iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
		iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssr_port} -j ACCEPT
		ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssr_port} -j ACCEPT
	fi
}
Del_iptables(){
	if [[ ! -z "${port}" ]]; then
		iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
		iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${port} -j ACCEPT
		ip6tables -D INPUT -m state --state NEW -m udp -p udp --dport ${port} -j ACCEPT
	fi
}
Save_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
	fi
}
Set_iptables(){
	if [[ ${release} == "centos" ]]; then
		service iptables save
		service ip6tables save
		chkconfig --level 2345 iptables on
		chkconfig --level 2345 ip6tables on
	else
		iptables-save > /etc/iptables.up.rules
		ip6tables-save > /etc/ip6tables.up.rules
		echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules\n/sbin/ip6tables-restore < /etc/ip6tables.up.rules' > /etc/network/if-pre-up.d/iptables
		chmod +x /etc/network/if-pre-up.d/iptables
	fi
}
# 读取 配置信息
Get_IP(){
	ip=$(wget -qO- -t1 -T2 ipinfo.io/ip)
	if [[ -z "${ip}" ]]; then
		ip=$(wget -qO- -t1 -T2 api.ip.sb/ip)
		if [[ -z "${ip}" ]]; then
			ip=$(wget -qO- -t1 -T2 members.3322.org/dyndns/getip)
			if [[ -z "${ip}" ]]; then
				ip="VPS_IP"
			fi
		fi
	fi
}
Get_User_info(){
	Get_user_port=$1
	user_info_get=$(python mujson_mgr.py -l -p "${Get_user_port}")
	match_info=$(echo "${user_info_get}"|grep -w "### user ")
	if [[ -z "${match_info}" ]]; then
		echo -e "${Error} Ulanyjylar barada maglumatlary alyp bilmedik! ${Green}[Port: ${ssr_port}]${Font_default} " && exit 1
	fi
	user_name=$(echo "${user_info_get}"|grep -w "user :"|awk -F "user : " '{print $NF}')
	port=$(echo "${user_info_get}"|grep -w "port :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	password=$(echo "${user_info_get}"|grep -w "passwd :"|awk -F "passwd : " '{print $NF}')
	method=$(echo "${user_info_get}"|grep -w "method :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol=$(echo "${user_info_get}"|grep -w "protocol :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	protocol_param=$(echo "${user_info_get}"|grep -w "protocol_param :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	[[ -z ${protocol_param} ]] && protocol_param="0(неограниченно)"
	obfs=$(echo "${user_info_get}"|grep -w "obfs :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	#transfer_enable=$(echo "${user_info_get}"|grep -w "transfer_enable :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}'|awk -F "ytes" '{print $1}'|sed 's/KB/ KB/;s/MB/ MB/;s/GB/ GB/;s/TB/ TB/;s/PB/ PB/')
	#u=$(echo "${user_info_get}"|grep -w "u :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	#d=$(echo "${user_info_get}"|grep -w "d :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	forbidden_port=$(echo "${user_info_get}"|grep -w "forbidden_port :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	[[ -z ${forbidden_port} ]] && forbidden_port="неограниченно"
	speed_limit_per_con=$(echo "${user_info_get}"|grep -w "speed_limit_per_con :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	speed_limit_per_user=$(echo "${user_info_get}"|grep -w "speed_limit_per_user :"|sed 's/[[:space:]]//g'|awk -F ":" '{print $NF}')
	Get_User_transfer "${port}"
}
Get_User_transfer(){
	transfer_port=$1
	#echo "transfer_port=${transfer_port}"
	all_port=$(${jq_file} '.[]|.port' ${config_user_mudb_file})
	#echo "all_port=${all_port}"
	port_num=$(echo "${all_port}"|grep -nw "${transfer_port}"|awk -F ":" '{print $1}')
	#echo "port_num=${port_num}"
	port_num_1=$(echo $((${port_num}-1)))
	#echo "port_num_1=${port_num_1}"
	transfer_enable_1=$(${jq_file} ".[${port_num_1}].transfer_enable" ${config_user_mudb_file})
	#echo "transfer_enable_1=${transfer_enable_1}"
	u_1=$(${jq_file} ".[${port_num_1}].u" ${config_user_mudb_file})
	#echo "u_1=${u_1}"
	d_1=$(${jq_file} ".[${port_num_1}].d" ${config_user_mudb_file})
	#echo "d_1=${d_1}"
	transfer_enable_Used_2_1=$(echo $((${u_1}+${d_1})))
	#echo "transfer_enable_Used_2_1=${transfer_enable_Used_2_1}"
	transfer_enable_Used_1=$(echo $((${transfer_enable_1}-${transfer_enable_Used_2_1})))
	#echo "transfer_enable_Used_1=${transfer_enable_Used_1}"
	
	if [[ ${transfer_enable_1} -lt 1024 ]]; then
		transfer_enable="${transfer_enable_1} B"
	elif [[ ${transfer_enable_1} -lt 1048576 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1024'}')
		transfer_enable="${transfer_enable} KB"
	elif [[ ${transfer_enable_1} -lt 1073741824 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1048576'}')
		transfer_enable="${transfer_enable} MB"
	elif [[ ${transfer_enable_1} -lt 1099511627776 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1073741824'}')
		transfer_enable="${transfer_enable} GB"
	elif [[ ${transfer_enable_1} -lt 1125899906842624 ]]; then
		transfer_enable=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_1}'/'1099511627776'}')
		transfer_enable="${transfer_enable} TB"
	fi
	#echo "transfer_enable=${transfer_enable}"
	if [[ ${u_1} -lt 1024 ]]; then
		u="${u_1} B"
	elif [[ ${u_1} -lt 1048576 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1024'}')
		u="${u} KB"
	elif [[ ${u_1} -lt 1073741824 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1048576'}')
		u="${u} MB"
	elif [[ ${u_1} -lt 1099511627776 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1073741824'}')
		u="${u} GB"
	elif [[ ${u_1} -lt 1125899906842624 ]]; then
		u=$(awk 'BEGIN{printf "%.2f\n",'${u_1}'/'1099511627776'}')
		u="${u} TB"
	fi
	#echo "u=${u}"
	if [[ ${d_1} -lt 1024 ]]; then
		d="${d_1} B"
	elif [[ ${d_1} -lt 1048576 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1024'}')
		d="${d} KB"
	elif [[ ${d_1} -lt 1073741824 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1048576'}')
		d="${d} MB"
	elif [[ ${d_1} -lt 1099511627776 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1073741824'}')
		d="${d} GB"
	elif [[ ${d_1} -lt 1125899906842624 ]]; then
		d=$(awk 'BEGIN{printf "%.2f\n",'${d_1}'/'1099511627776'}')
		d="${d} TB"
	fi
	#echo "d=${d}"
	if [[ ${transfer_enable_Used_1} -lt 1024 ]]; then
		transfer_enable_Used="${transfer_enable_Used_1} B"
	elif [[ ${transfer_enable_Used_1} -lt 1048576 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1024'}')
		transfer_enable_Used="${transfer_enable_Used} KB"
	elif [[ ${transfer_enable_Used_1} -lt 1073741824 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1048576'}')
		transfer_enable_Used="${transfer_enable_Used} MB"
	elif [[ ${transfer_enable_Used_1} -lt 1099511627776 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1073741824'}')
		transfer_enable_Used="${transfer_enable_Used} GB"
	elif [[ ${transfer_enable_Used_1} -lt 1125899906842624 ]]; then
		transfer_enable_Used=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_1}'/'1099511627776'}')
		transfer_enable_Used="${transfer_enable_Used} TB"
	fi
	#echo "transfer_enable_Used=${transfer_enable_Used}"
	if [[ ${transfer_enable_Used_2_1} -lt 1024 ]]; then
		transfer_enable_Used_2="${transfer_enable_Used_2_1} B"
	elif [[ ${transfer_enable_Used_2_1} -lt 1048576 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1024'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} KB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1073741824 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1048576'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} MB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1099511627776 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1073741824'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} GB"
	elif [[ ${transfer_enable_Used_2_1} -lt 1125899906842624 ]]; then
		transfer_enable_Used_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_2_1}'/'1099511627776'}')
		transfer_enable_Used_2="${transfer_enable_Used_2} TB"
	fi
	#echo "transfer_enable_Used_2=${transfer_enable_Used_2}"
}
Get_User_transfer_all(){
	if [[ ${transfer_enable_Used_233} -lt 1024 ]]; then
		transfer_enable_Used_233_2="${transfer_enable_Used_233} B"
	elif [[ ${transfer_enable_Used_233} -lt 1048576 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1024'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} KB"
	elif [[ ${transfer_enable_Used_233} -lt 1073741824 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1048576'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} MB"
	elif [[ ${transfer_enable_Used_233} -lt 1099511627776 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1073741824'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} GB"
	elif [[ ${transfer_enable_Used_233} -lt 1125899906842624 ]]; then
		transfer_enable_Used_233_2=$(awk 'BEGIN{printf "%.2f\n",'${transfer_enable_Used_233}'/'1099511627776'}')
		transfer_enable_Used_233_2="${transfer_enable_Used_233_2} TB"
	fi
}
urlsafe_base64(){
	date=$(echo -n "$1"|base64|sed ':a;N;s/\n/ /g;ta'|sed 's/ //g;s/=//g;s/+/-/g;s/\//_/g')
	echo -e "${date}"
}
ss_link_qr(){
	SSbase64=$(urlsafe_base64 "${method}:${password}@${ip}:${port}")
	SSurl="ss://${SSbase64}"
	SSQRcode="https://api.qrserver.com/v1/create-qr-code/?data=${SSurl}"
	ss_link="${SSurl}"
	tg_ss_link=%60${SSurl}%60
}
ssr_link_qr(){
	SSRprotocol=$(echo ${protocol} | sed 's/_compatible//g')
	SSRobfs=$(echo ${obfs} | sed 's/_compatible//g')
	SSRPWDbase64=$(urlsafe_base64 "${password}")
	SSRbase64=$(urlsafe_base64 "${ip}:${port}:${SSRprotocol}:${method}:${SSRobfs}:${SSRPWDbase64}")
	SSRurl="ssr://${SSRbase64}"
	SSRQRcode="https://api.qrserver.com/v1/create-qr-code/?data=${SSRurl}"
	ssr_link="${SSRurl}"
	tg_ssr_link=%60${SSRurl}%60
}

ss_ssr_determine(){
	protocol_suffix=`echo ${protocol} | awk -F "_" '{print $NF}'`
	obfs_suffix=`echo ${obfs} | awk -F "_" '{print $NF}'`
	if [[ ${protocol} = "origin" ]]; then
		if [[ ${obfs} = "plain" ]]; then
			ss_link_qr
			ssr_link=""
		else
			if [[ ${obfs_suffix} != "compatible" ]]; then
				ss_link=""
			else
				ss_link_qr
			fi
		fi
	else
		if [[ ${protocol_suffix} != "compatible" ]]; then
			ss_link=""
		else
			if [[ ${obfs_suffix} != "compatible" ]]; then
				if [[ ${obfs_suffix} = "plain" ]]; then
					ss_link_qr
				else
					ss_link=""
				fi
			else
				ss_link_qr
			fi
		fi
	fi
	ssr_link_qr
}
# Display configuration information
View_User(){
	SSR_installation_status
	List_port_user
	while true
	do
		echo -e "Analiz üçin akaundyň portyny ýazyň"
		read -e -p "(По умолчанию: ýatyrmak):" View_user_port
		[[ -z "${View_user_port}" ]] && echo -e "Ýatyrylýar..." && exit 1
		View_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${View_user_port}"',')
		if [[ ! -z ${View_user} ]]; then
			Get_User_info "${View_user_port}"
			View_User_info
			break
		else
			echo -e "${Error} Dogry porty ýazyň !"
		fi
	done
}
View_User_info(){
	ip=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
	[[ -z "${ip}" ]] && Get_IP
	ss_ssr_determine
	clear && echo "===================================================" && echo
	echo -e " Ulanyjy barada maglumat [${user_name}] ：" && echo
	echo -e " IP\t    : ${Red}${ip}${Font_default}"
	echo -e " Porty\t    : ${Red}${port}${Font_default}"
	echo -e " Kody\t    : ${Red}${password}${Font_default}"
	echo -e " Kodlamasy : ${Red}${method}${Font_default}"
	echo -e " Protokoly   : ${Red}${protocol}${Font_default}"
	echo -e " Obfs\t    : ${Red}${obfs}${Font_default}"
	echo -e " Enjamlaryň sany : ${Red}${protocol_param}${Font_default}"
	echo -e " Açaryň umumy tizligi : ${Red}${speed_limit_per_con} KB/S${Font_default}"
	echo -e " Her ulanyjydaky açaryň tizligi : ${Red}${speed_limit_per_user} KB/S${Font_default}"
	echo -e " Gadagan portlar : ${Red}${forbidden_port} ${Font_default}"
	echo
	echo -e " Ulanylan trafik : Upload: ${Red}${u}${Font_default} + Download: ${Red}${d}${Font_default} = ${Red}${transfer_enable_Used_2}${Font_default}"
	echo -e " Galan trafik : ${Red}${transfer_enable_Used} ${Font_default}"
	echo -e " Jemi trafik : ${Red}${transfer_enable} ${Font_default}"
	echo -e "${Red}SS açary:${Font_default} ${ss_link}"
	echo -e "${Red}SSR açary:${Font_default} ${ssr_link}"
	echo && echo "==================================================="
}
# Создание юзера
Set_config_user(){
	echo "Ulanyjynyň ady (Awto görkezilen sene)"
	read -e -p "(По умолчанию: Admin):" ssr_user
	[[ -z "${ssr_user}" ]] && ssr_user="Admin"
	ssr_user=$(echo "${ssr_user}_${admacc}_$(date +"%d/%m")" |sed 's/ //g')
	echo && echo -e ${Separator_1} && echo -e "	Ulanyjynyň ady : ${Green}${ssr_user}${Font_default}" && echo -e ${Separator_1} && echo
}
Set_config_port(){
	echo -e "
${Purple}|————————————————————————————————————|${Font_default}
${Purple}|—————————— ${Red}Port döredildi${Purple}———————————${Font_default}${Purple}|${Font_default}	
${Purple}|————————————————————————————————————|${Font_default} "
	ssr_port=$(shuf -i 100-999 -n 1)
	while true
	do
	echo $((${ssr_port}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_port} -ge 100 ]] && [[ ${ssr_port} -le 999 ]]; then
		echo -e ${Separator_1} && echo -e "	  ${Red} Port: : ${Ocean}${ssr_port}${Font_default}" && echo -e ${Separator_1}
			break
		else
			echo -e "${Error} Dogry porty saýlaň(1-9999)"
		fi
	else
		echo -e "${Error} Dogry porty saýlaň(1-9999)"
	fi
	done
}
Set_config_password(){
	ssr_password=$(date +%s%N | md5sum | head -c 16)
	echo -e "
${Purple}|————————————————————————————————————|${Font_default}
${Purple}|——————— ${Red}parol döredildi ${Purple}————————${Font_default}${Purple}|${Font_default}	
${Purple}|————————————————————————————————————|${Font_default} "
}
Set_config_method(){
	ssr_method="aes-256-cfb"
	echo -e ${Separator_1} && echo -e " ${Red}Kodlamasy : ${Ocean}${ssr_method}${Font_default}" && echo -e ${Separator_1}
}
Set_config_protocol(){
ssr_protocol="origin"
}
Set_config_protocol_slow(){
	echo -e "Protokol
	
 ${Green}1.${Font_default} origin
 ${Green}2.${Font_default} auth_sha1_v4
 ${Green}3.${Font_default} auth_aes128_md5
 ${Green}4.${Font_default} auth_aes128_sha1
 ${Green}5.${Font_default} auth_chain_a
 ${Green}6.${Font_default} auth_chain_b
 ${Tip} Eger siz auth_chain_* tipde kodlama isleseňiz gowusy none ulanyň (Sebabi bu kodlamady RC4 bar)，olam problema ýüze çykaryp biler" && echo
	read -e -p "(По умолчанию: 3. auth_aes128_md5):" ssr_protocol
	[[ -z "${ssr_protocol}" ]] && ssr_protocol="1"
	if [[ ${ssr_protocol} == "1" ]]; then
		ssr_protocol="origin"
	elif [[ ${ssr_protocol} == "2" ]]; then
		ssr_protocol="auth_sha1_v4"
	elif [[ ${ssr_protocol} == "3" ]]; then
		ssr_protocol="auth_aes128_md5"
	elif [[ ${ssr_protocol} == "4" ]]; then
		ssr_protocol="auth_aes128_sha1"
	elif [[ ${ssr_protocol} == "5" ]]; then
		ssr_protocol="auth_chain_a"
	elif [[ ${ssr_protocol} == "6" ]]; then
		ssr_protocol="auth_chain_b"
	else
		ssr_protocol="origin"
	fi
	echo && echo -e ${Separator_1} && echo -e "	Protokol : ${Green}${ssr_protocol}${Font_default}" && echo -e ${Separator_1} && echo
	if [[ ${ssr_protocol} != "origin" ]]; then
		if [[ ${ssr_protocol} == "auth_sha1_v4" ]]; then
			read -e -p "Bu protokol original wersiýa bilen birleşen(_compatible)？[Y/n]" ssr_protocol_yn
			[[ -z "${ssr_protocol_yn}" ]] && ssr_protocol_yn="y"
			[[ $ssr_protocol_yn == [Yy] ]] && ssr_protocol=${ssr_protocol}"_compatible"
			echo
		fi
	fi
}
Set_config_obfs(){
ssr_obfs="plain"
}
Set_config_obfs_slow(){
	echo -e "plug-in üçin obfs saýlaň
	
 ${Green}1.${Font_default} plain
 ${Green}2.${Font_default} http_simple
 ${Green}3.${Font_default} http_post
 ${Green}4.${Font_default} random_head
 ${Green}5.${Font_default} tls1.2_ticket_auth
 ${Tip} Неинтересная информация на китайском языке бла бла !" && echo
	read -e -p "(По умолчанию: 1. plain):" ssr_obfs
	[[ -z "${ssr_obfs}" ]] && ssr_obfs="1"
	if [[ ${ssr_obfs} == "1" ]]; then
		ssr_obfs="plain"
	elif [[ ${ssr_obfs} == "2" ]]; then
		ssr_obfs="http_simple"
	elif [[ ${ssr_obfs} == "3" ]]; then
		ssr_obfs="http_post"
	elif [[ ${ssr_obfs} == "4" ]]; then
		ssr_obfs="random_head"
	elif [[ ${ssr_obfs} == "5" ]]; then
		ssr_obfs="tls1.2_ticket_auth"
	else
		ssr_obfs="plain"
	fi
	echo && echo -e ${Separator_1} && echo -e "	Obfs : ${Green}${ssr_obfs}${Font_default}" && echo -e ${Separator_1} && echo
	if [[ ${ssr_obfs} != "plain" ]]; then
			read -e -p "Bu protokol original wersiýa bilen birleşen(_compatible)？[Y/n]" ssr_obfs_yn
			[[ -z "${ssr_obfs_yn}" ]] && ssr_obfs_yn="y"
			[[ $ssr_obfs_yn == [Yy] ]] && ssr_obfs=${ssr_obfs}"_compatible"
			echo
	fi
}
Set_config_protocol_param(){
	while true
	do
	ssr_protocol_param=""
	[[ -z "$ssr_protocol_param" ]] && ssr_protocol_param="" && break
	echo $((${ssr_protocol_param}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_protocol_param} -ge 100 ]] && [[ ${ssr_protocol_param} -le 999 ]]; then
			break
		else
			echo -e "${Error} Dogry nomeri saýlaň(1-9999)"
		fi
	else
		echo -e "${Error} Dogry nomeri saýlaň(1-9999)"
	fi
	done
}
Set_config_protocol_param_slow(){
	while true
	do
	echo -e "Bir wagtda näçe ulanyjy baglanyp bilsin?"
	echo -e "${Tip} 2 enjamdan köp ulanylsa gowy bolar"
	read -e -p "(По умолчанию: çäksiz):" ssr_protocol_param
	[[ -z "$ssr_protocol_param" ]] && ssr_protocol_param="" && echo && break
	echo $((${ssr_protocol_param}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_protocol_param} -ge 1 ]] && [[ ${ssr_protocol_param} -le 9999 ]]; then
			echo && echo -e ${Separator_1} && echo -e "	Enjam limidi : ${Green}${ssr_protocol_param}${Font_default}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Dogry nomeri saýlaň(1-9999)"
		fi
	else
		echo -e "${Error} Dogry nomeri saýlaň(1-9999)"
	fi
	done
}
Set_config_speed_limit_per_con(){
	while true
	do
	ssr_speed_limit_per_con=""
	[[ -z "$ssr_speed_limit_per_con" ]] && ssr_speed_limit_per_con=0 && break
	echo $((${ssr_speed_limit_per_con}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_con} -ge 1 ]] && [[ ${ssr_speed_limit_per_con} -le 131072 ]]; then
			break
		else
			echo -e "${Error} Dogry nomeri saýlaň(1-131072)"
		fi
	else
		echo -e "${Error} Dogry nomeri saýlaň(1-131072)"
	fi
	done
}
Set_config_speed_limit_per_con_slow(){
	while true
	do
	echo -e "Bir açar üçin maksimum tizlik (KB/S)"
	echo -e "${Tip} Duýduryş: bu sazlamalar hemme açarlara täsir edip biler"
	read -e -p "(По умолчанию: çäksiz):" ssr_speed_limit_per_con
	[[ -z "$ssr_speed_limit_per_con" ]] && ssr_speed_limit_per_con=0 && echo && break
	echo $((${ssr_speed_limit_per_con}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_con} -ge 1 ]] && [[ ${ssr_speed_limit_per_con} -le 131072 ]]; then
			echo && echo ${Separator_1} && echo -e "	Açar üçin tizlik limidi : ${Green}${ssr_speed_limit_per_con} KB/S${Font_default}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Dogry nomeri saýlaň(1-131072)"
		fi
	else
		echo -e "${Error} Dogry nomeri saýlaň(1-131072)"
	fi
	done	
}
Set_config_speed_limit_per_user(){
	while true
	do
	echo
	ssr_speed_limit_per_user=""
	[[ -z "$ssr_speed_limit_per_user" ]] && ssr_speed_limit_per_user=0 && break
	echo $((${ssr_speed_limit_per_user}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_user} -ge 1 ]] && [[ ${ssr_speed_limit_per_user} -le 131072 ]]; then
			break
		else
			echo -e "${Error} Dogry nomeri saýlaň(1-131072)"
		fi
	else
		echo -e "${Error} Dogry nomeri saýlaň(1-131072)"
	fi
	done
}
Set_config_speed_limit_per_user_slow(){
	while true
	do
	echo
	echo -e "Her ulanyjynyň açary üçin tizlik limidi(KB/S)"
	echo -e "${Tip} Нифига не понял что здесь было。"
	read -e -p "(По умолчанию: çäksiz):" ssr_speed_limit_per_user
	[[ -z "$ssr_speed_limit_per_user" ]] && ssr_speed_limit_per_user=0 && echo && break
	echo $((${ssr_speed_limit_per_user}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_speed_limit_per_user} -ge 1 ]] && [[ ${ssr_speed_limit_per_user} -le 131072 ]]; then
			echo && echo ${Separator_1} && echo -e "	Ulanyju üçin tizlik limidi : ${Green}${ssr_speed_limit_per_user} KB/S${Font_default}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Dogry nomeri saýlaň(1-131072)"
		fi
	else
		echo -e "${Error} Dogry nomeri saýlaň(1-131072)"
	fi
	done	
}
Set_config_transfer(){
	while true
	do
	echo
	ssr_transfer=""
	[[ -z "$ssr_transfer" ]] && ssr_transfer="838868" && break
	echo $((${ssr_transfer}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_transfer} -ge 1 ]] && [[ ${ssr_transfer} -le 838868 ]]; then
			break
		else
			echo -e "${Error} Dogry nomeri saýlaň(1-838868)"
		fi
	else
		echo -e "${Error} Dogry nomeri saýlaň(1-838868)"
	fi
	done
}
Set_config_transfer_slow(){
	while true
	do
	echo
	echo -e "Bir açar üçin maksimum trafik(GB, 1-838868 GB)"
	read -e -p "(По умолчанию: çäksiz):" ssr_transfer
	[[ -z "$ssr_transfer" ]] && ssr_transfer="838868" && echo && break
	echo $((${ssr_transfer}+0)) &>/dev/null
	if [[ $? == 0 ]]; then
		if [[ ${ssr_transfer} -ge 1 ]] && [[ ${ssr_transfer} -le 838868 ]]; then
			echo && echo ${Separator_1} && echo -e "	Jemi trafik : ${Green}${ssr_transfer} GB${Font_default}" && echo ${Separator_1} && echo
			break
		else
			echo -e "${Error} Dogry nomeri saýlaň(1-838868)"
		fi
	else
		echo -e "${Error} Dogry nomeri saýlaň(1-838868)"
	fi
	done
}
Set_config_forbid(){
	ssr_forbid=""
	[[ -z "${ssr_forbid}" ]] && ssr_forbid=""
}
Set_config_forbid_slow(){
	echo "Gadagan edilmeli porty giriziň"
	echo -e "${Tip} Пример: Запретив 25ый Port, вы запретите доступ к сервисам почты
Единичный Port: 25
Несколько Portов: 23,465
Диапазон Portов: 233-266
Смешанный формат: 25,465,233-666 "
	read -e -p "(По умолчанию: hemme portlar açyk):" ssr_forbid
	[[ -z "${ssr_forbid}" ]] && ssr_forbid=""
	echo && echo ${Separator_1} && echo -e "	Gadagan edilen portlar : ${Green}${ssr_forbid}${Font_default}" && echo ${Separator_1} && echo
}
Set_config_enable(){
	user_total=$(echo $((${user_total}-1)))
	for((integer = 0; integer <= ${user_total}; integer++))
	do
		echo -e "integer=${integer}"
		port_jq=$(${jq_file} ".[${integer}].port" "${config_user_mudb_file}")
		echo -e "port_jq=${port_jq}"
		if [[ "${ssr_port}" == "${port_jq}" ]]; then
			enable=$(${jq_file} ".[${integer}].enable" "${config_user_mudb_file}")
			echo -e "enable=${enable}"
			[[ "${enable}" == "null" ]] && echo -e "${Error} Не удалось получить отключенный статус текущего Portа [${ssr_port}]!" && exit 1
			ssr_port_num=$(cat "${config_user_mudb_file}"|grep -n '"port": '${ssr_port}','|awk -F ":" '{print $1}')
			echo -e "ssr_port_num=${ssr_port_num}"
			[[ "${ssr_port_num}" == "null" ]] && echo -e "${Error} Не удалось получить количество строк текущего Portа[${ssr_port}]!" && exit 1
			ssr_enable_num=$(echo $((${ssr_port_num}-5)))
			echo -e "ssr_enable_num=${ssr_enable_num}"
			break
		fi
	done
	if [[ "${enable}" == "1" ]]; then
		echo -e "Port [${ssr_port}] находится в состоянии：${Green}включен${Font_default} , сменить статус на ${Red}выключен${Font_default} ?[Y/n]"
		read -e -p "(По умолчанию: Y):" ssr_enable_yn
		[[ -z "${ssr_enable_yn}" ]] && ssr_enable_yn="y"
		if [[ "${ssr_enable_yn}" == [Yy] ]]; then
			ssr_enable="0"
		else
			echo "Ýatyr..." && exit 0
		fi
	elif [[ "${enable}" == "0" ]]; then
		echo -e "Port [${ssr_port}] находится в состоянии：${Green}отключен${Font_default} , сменить статус на  ${Red}включен${Font_default} ?[Y/n]"
		read -e -p "(По умолчанию: Y):" ssr_enable_yn
		[[ -z "${ssr_enable_yn}" ]] && ssr_enable_yn = "y"
		if [[ "${ssr_enable_yn}" == [Yy] ]]; then
			ssr_enable="1"
		else
			echo "Ýatyr..." && exit 0
		fi
	else
		echo -e "${Error} какая то ошибка с акком, гг[${enable}] !" && exit 1
	fi
}
Set_user_api_server_pub_addr(){
	addr=$1
	if [[ "${addr}" == "Modify" ]]; then
		server_pub_addr=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
		if [[ -z ${server_pub_addr} ]]; then
			echo -e "${Error} Serweriň IP-syny alyp bilmedik！" && exit 1
		else
			echo -e "${Info} Häzirki IP： ${Green}${server_pub_addr}${Font_default}"
		fi
	fi
	echo "Serwer IP-syny giriziň"
	read -e -p "(IP-ny awtomatiçeski tapdyrmak üçin ENTER-a basyň!):" ssr_server_pub_addr
	if [[ -z "${ssr_server_pub_addr}" ]]; then
		Get_IP
		if [[ ${ip} == "VPS_IP" ]]; then
			while true
			do
			read -e -p "${Error} Serwer IP-syny özuňiz giriziň!" ssr_server_pub_addr
			if [[ -z "$ssr_server_pub_addr" ]]; then
				echo -e "${Error} Boş bolmaly däl！"
			else
				break
			fi
			done
		else
			ssr_server_pub_addr="${ip}"
		fi
	fi
	echo && echo -e ${Separator_1} && echo -e "	Serwer IP-sy : ${Green}${ssr_server_pub_addr}${Font_default}" && echo -e ${Separator_1} && echo
}

whattodo(){
	echo -e "Nädip täze ulanyjy goşmaly?
	${Green}1.${Font_default}Çalt (çäksiz)
	${Red}2.${Font_default}Çägi ozüňiz giriziň"
	read -e -p "(По умолчанию: Çalt ):" howtosetup
	[[ -z "${howtosetup}" ]] && howtosetup="1"
	if [[ ${howtosetup} == "1" ]]; then
		Set_config_all
	elif [[ ${howtosetup} == "2" ]]; then
		Set_config_all_slow
	else
		Set_config_all
	fi
}
Set_config_all_slow(){
	lal=$1
	if [[ "${lal}" == "Modify" ]]; then
		DealersList
		Set_config_password
		Set_config_method
		Set_config_protocol_slow
		Set_config_obfs_slow
		Set_config_protocol_param_slow
		Set_config_speed_limit_per_con_slow
		Set_config_speed_limit_per_user_slow
		Set_config_transfer_slow
		Set_config_forbid_slow
	else
		DealersList
		Set_config_user
		Set_config_port
		Set_config_password
		Set_config_method
		Set_config_protocol_slow
		Set_config_obfs_slow
		Set_config_protocol_param_slow
		Set_config_speed_limit_per_con_slow
		Set_config_speed_limit_per_user_slow
		Set_config_transfer_slow
		Set_config_forbid_slow
	fi
}
Set_config_all(){
	lal=$1
	if [[ "${lal}" == "Modify" ]]; then
		DealersList
		Set_config_password
		Set_config_method
		Set_config_protocol
		Set_config_obfs
		Set_config_protocol_param
		Set_config_speed_limit_per_con
		Set_config_speed_limit_per_user
		Set_config_transfer
		Set_config_forbid
	else
		DealersList
		Set_config_user
		Set_config_port
		Set_config_password
		Set_config_method
		Set_config_protocol
		Set_config_obfs
		Set_config_protocol_param
		Set_config_speed_limit_per_con
		Set_config_speed_limit_per_user
		Set_config_transfer
		Set_config_forbid
	fi
}
# Изменить конфигурацию клиента
Modify_config_password(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -k "${ssr_password}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Ulanyjynyň parolyny üýtgedip bolmady! ${Green}[Port: ${ssr_port}]${Font_default} " && exit 1
	else
		echo -e "${Info} Ulanyjynyň paroly Üstünlikli üýtgedildi! ${Green}[Port: ${ssr_port}]${Font_default} (10 sekundyň içinde zanit bolup biler!)"
	fi
}
Modify_config_method(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -m "${ssr_method}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Kodlamany üýtgedip bolmady! ${Green}[Port: ${ssr_port}]${Font_default} " && exit 1
	else
		echo -e "${Info} Kodlama üstünlikli üýtgedildi! ${Green}[Port: ${ssr_port}]${Font_default} (10 sekundyň içinde zanit bolup biler!)"
	fi
}
Modify_config_protocol(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -O "${ssr_protocol}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Protokoly üýtgedip bolmady! ${Green}[Port: ${ssr_port}]${Font_default} " && exit 1
	else
		echo -e "${Info} Protokol üstünlikli üýtgedildi! ${Green}[Port: ${ssr_port}]${Font_default} (10 sekundyň içinde zanit bolup biler!)"
	fi
}
Modify_config_obfs(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -o "${ssr_obfs}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Obfs plugin-i üýtgedip bolmady! ${Green}[Port: ${ssr_port}]${Font_default} " && exit 1
	else
		echo -e "${Info} Obfs plugin-i üstünlikli üýgetdik! ${Green}[Port: ${ssr_port}]${Font_default} (10 sekundyň içinde zanit bolup biler!)"
	fi
}
Modify_config_protocol_param(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -G "${ssr_protocol_param}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Enjam başyna limidi üýtgedip bilmedik! ${Green}[Port: ${ssr_port}]${Font_default} " && exit 1
	else
		echo -e "${Info} Enjam başyna limit üýtgedildi! ${Green}[Port: ${ssr_port}]${Font_default} (10 sekundyň içinde zanit bolup biler!)"
	fi
}
Modify_config_speed_limit_per_con(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -s "${ssr_speed_limit_per_con}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Açar tizliginiň limidini üýtgedip bilmedik! ${Green}[Port: ${ssr_port}]${Font_default} " && exit 1
	else
		echo -e "${Info} Açar tizliginiň limidi üýtgedildi! ${Green}[Port: ${ssr_port}]${Font_default} (10 sekundyň içinde zanit bolup biler!)"
	fi
}
Modify_config_speed_limit_per_user(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -S "${ssr_speed_limit_per_user}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Ulanyjylaryň tizliginiň limidini üýtgedip bilmedik! ${Green}[Port: ${ssr_port}]${Font_default} " && exit 1
	else
		echo -e "${Info} Ulanyjylaryň tizliginiň limidi üstünlikli üýtgedildi! ${Green}[Port: ${ssr_port}]${Font_default} (10 sekundyň içinde zanit bolup biler!)"
	fi
}
Modify_config_connect_verbose_info(){
	sed -i 's/"connect_verbose_info": '"$(echo ${connect_verbose_info})"',/"connect_verbose_info": '"$(echo ${ssr_connect_verbose_info})"',/g' ${config_user_file}
}
Modify_config_transfer(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -t "${ssr_transfer}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Ulanyjynyň umumy trafigini üýtgedip bilmedik! ${Green}[Port: ${ssr_port}]${Font_default} " && exit 1
	else
		echo -e "${Info} Ulanyjynyň umumy trafigi üýtgedildi! ${Green}[Port: ${ssr_port}]${Font_default} (10 sekundyň içinde zanit bolup biler!)"
	fi
}
Modify_config_forbid(){
	match_edit=$(python mujson_mgr.py -e -p "${ssr_port}" -f "${ssr_forbid}"|grep -w "edit user ")
	if [[ -z "${match_edit}" ]]; then
		echo -e "${Error} Ulanyja gadagan portlary üýtgedip bilmedik! ${Green}[Port: ${ssr_port}]${Font_default} " && exit 1
	else
		echo -e "${Info} Ulanyja gadagan portlar üýtgedildi! ${Green}[Port: ${ssr_port}]${Font_default} (10 sekundyň içinde zanit bolup biler!)"
	fi
}
Modify_config_enable(){
	sed -i "${ssr_enable_num}"'s/"enable": '"$(echo ${enable})"',/"enable": '"$(echo ${ssr_enable})"',/' ${config_user_mudb_file}
}
Modify_user_api_server_pub_addr(){
	sed -i "s/SERVER_PUB_ADDR = '${server_pub_addr}'/SERVER_PUB_ADDR = '${ssr_server_pub_addr}'/" ${config_user_api_file}
}
Modify_config_all(){
	Modify_config_password
	Modify_config_method
	Modify_config_protocol
	Modify_config_obfs
	Modify_config_protocol_param
	Modify_config_speed_limit_per_con
	Modify_config_speed_limit_per_user
	Modify_config_transfer
	Modify_config_forbid
}
Check_python(){
	python_ver=`python -h`
	if [[ -z ${python_ver} ]]; then
		echo -e "${Info} Python gurnalmadyk, gurnap başlaň..."
		if [[ ${release} == "centos" ]]; then
			yum install -y python
		else
			apt-get install -y python
		fi
	fi
}
Centos_yum(){
	yum update
	cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
	if [[ $? = 0 ]]; then
		yum install -y vim unzip crond net-tools
	else
		yum install -y vim unzip crond
	fi
}
Debian_apt(){
	apt-get update
	cat /etc/issue |grep 9\..*>/dev/null
	if [[ $? = 0 ]]; then
		apt-get install -y vim unzip cron net-tools
	else
		apt-get install -y vim unzip cron
	fi
}
# 下载 ShadowsocksR
Download_SSR(){
	cd "/usr/local"
	wget -N --no-check-certificate "https://github.com/ToyoDAdoubiBackup/shadowsocksr/archive/manyuser.zip"
	#git config --global http.sslVerify false
	#env GIT_SSL_NO_VERIFY=true git clone -b manyuser https://github.com/ToyoDAdoubiBackup/shadowsocksr.git
	#[[ ! -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR服务端 下载失败 !" && exit 1
	[[ ! -e "manyuser.zip" ]] && echo -e "${Error} ShadowsocksR arhiwini ýükläp bilmedik !" && rm -rf manyuser.zip && exit 1
	unzip "manyuser.zip"
	[[ ! -e "/usr/local/shadowsocksr-manyuser/" ]] && echo -e "${Error} ShadowsocksR pakedyny açmakda ýalňyşlyk döredi !" && rm -rf manyuser.zip && exit 1
	mv "/usr/local/shadowsocksr-manyuser/" "/usr/local/shadowsocksr/"
	[[ ! -e "/usr/local/shadowsocksr/" ]] && echo -e "${Error} ShadowsocksR adyny üýtgedip bilmedik !" && rm -rf manyuser.zip && rm -rf "/usr/local/shadowsocksr-manyuser/" && exit 1
	rm -rf manyuser.zip
	cd "shadowsocksr"
	cp "${ssr_folder}/config.json" "${config_user_file}"
	cp "${ssr_folder}/mysql.json" "${ssr_folder}/usermysql.json"
	cp "${ssr_folder}/apiconfig.py" "${config_user_api_file}"
	[[ ! -e ${config_user_api_file} ]] && echo -e "${Error} ShadowsocksR apiconfig.py-syny kopyalap bilmedik  !" && exit 1
	sed -i "s/API_INTERFACE = 'sspanelv2'/API_INTERFACE = 'mudbjson'/" ${config_user_api_file}
	server_pub_addr="127.0.0.1"
	Modify_user_api_server_pub_addr
	#sed -i "s/SERVER_PUB_ADDR = '127.0.0.1'/SERVER_PUB_ADDR = '${ip}'/" ${config_user_api_file}
	sed -i 's/ \/\/ only works under multi-user mode//g' "${config_user_file}"
	echo -e "${Info} ShadowsocksR üstünlikli işledildi !"
}
Service_SSR(){
	if [[ ${release} = "centos" ]]; then
		if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/service/ssrmu_centos -O /etc/init.d/ssrmu; then
			echo -e "${Error} ShadowsocksR kontrol ediş skriptini gurnap bilmedik !" && exit 1
		fi
		chmod +x /etc/init.d/ssrmu
		chkconfig --add ssrmu
		chkconfig ssrmu on
	else
		if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/service/ssrmu_debian -O /etc/init.d/ssrmu; then
			echo -e "${Error} ShadowsocksR kontrol ediş skriptini gurnap bilmedik !" && exit 1
		fi
		chmod +x /etc/init.d/ssrmu
		update-rc.d -f ssrmu defaults
	fi
	echo -e "${Info} ShadowsocksR kontrol ediş skripti gurnaldy !"
}
# 安装 JQ解析器
JQ_install(){
	if [[ ! -e ${jq_file} ]]; then
		cd "${ssr_folder}"
		if [[ ${bit} = "x86_64" ]]; then
			mv "jq-linux64" "jq"
			#wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64" -O ${jq_file}
		else
			mv "jq-linux32" "jq"
			#wget --no-check-certificate "https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux32" -O ${jq_file}
		fi
		[[ ! -e ${jq_file} ]] && echo -e "${Error} Парсер JQ не удалось переименовать !" && exit 1
		chmod +x ${jq_file}
		echo -e "${Info} Установка JQ завершена, продолжение..." 
	else
		echo -e "${Info} Парсер JQ успешно установлен..."
	fi
}
# 安装 依赖
Installation_dependency(){
	if [[ ${release} == "centos" ]]; then
		Centos_yum
	else
		Debian_apt
	fi
	[[ ! -e "/usr/bin/unzip" ]] && echo -e "${Error} Unzip-i ýükläp bilmedik !" && exit 1
	Check_python
	#echo "nameserver 8.8.8.8" > /etc/resolv.conf
	#echo "nameserver 8.8.4.4" >> /etc/resolv.conf
	\cp -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	if [[ ${release} == "centos" ]]; then
		/etc/init.d/crond restart
	else
		/etc/init.d/cron restart
	fi
}
Install_SSR(){
	check_root
	[[ -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR onsuzam ýüklenen !" && exit 1
	echo -e "${Info} типа че то происходит..."
	Set_user_api_server_pub_addr
	Set_config_all
	echo -e "${Info} Konfigi ýüklemek"
	Installation_dependency
	echo -e "${Info} Baglylyklary ýüklemek"
	Download_SSR
	echo -e "${Info} SSR-i gurnamak"
	Service_SSR
	echo -e "${Info} Serwis Nastroýkasy"
	JQ_install
	echo -e "${Info} JQ ýüklemek"
	Requirements_install
	echo -e "${Info} Baglylyklary gurnamak"
	Add_port_user "install"
	echo -e "${Info} Ulanyjy portyny goşmak"
	Set_iptables
	echo -e "${Info} Iptables Nastroýkasy"
	Add_iptables
	echo -e "${Info} Iptables Nastroýkasyny goşmak"
	Save_iptables
	echo -e "${Info} Iptables Nastroýkasyny Save etmek"
	Start_SSR
	Install_Libsodium
	Get_User_info "${ssr_port}"
	View_User_info
}
Update_SSR(){
	SSR_installation_status
	echo -e "Şuwagtky funksiýa öçürilen."
	#cd ${ssr_folder}
	#git pull
	#Restart_SSR
}
Uninstall_SSR(){
	[[ ! -e ${ssr_folder} ]] && echo -e "${Error} ShadowsocksR gurnalmadyk !" && exit 1
	echo "ShadowsocksR-y pozjakmy？[y/N]" && echo
	read -e -p "(По умолчанию: n):" unyn
	[[ -z ${unyn} ]] && unyn="n"
	if [[ ${unyn} == [Yy] ]]; then
		check_pid
		[[ ! -z "${PID}" ]] && kill -9 ${PID}
		user_info=$(python mujson_mgr.py -l)
		user_total=$(echo "${user_info}"|wc -l)
		if [[ ! -z ${user_info} ]]; then
			for((integer = 1; integer <= ${user_total}; integer++))
			do
				port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
				Del_iptables
			done
			Save_iptables
		fi
		if [[ ! -z $(crontab -l | grep "ssrmu.sh") ]]; then
			crontab_monitor_ssr_cron_stop
			Clear_transfer_all_cron_stop
		fi
		if [[ ${release} = "centos" ]]; then
			chkconfig --del ssrmu
		else
			update-rc.d -f ssrmu remove
		fi
		rm -rf ${ssr_folder} && rm -rf /etc/init.d/ssrmu
		echo && echo " ShadowsocksR üstünlikli pozuldy !" && echo
	else
		echo && echo " Ýatyrylýar..." && echo
	fi
}
Check_Libsodium_ver(){
	echo -e "${Info} Libsodium-yň soňky wersiýasy alynýar..."
	Libsodiumr_ver=$(wget -qO- "https://github.com/jedisct1/libsodium/tags"|grep "/jedisct1/libsodium/releases/tag/"|head -1|sed -r 's/.*tag\/(.+)\">.*/\1/')
	[[ -z ${Libsodiumr_ver} ]] && Libsodiumr_ver=${Libsodiumr_ver_backup}
	echo -e "${Info} Libsodium-yň soňky wersiýasy: ${Green}${Libsodiumr_ver}${Font_default} !"
}
Install_Libsodium(){
	if [[ -e ${Libsodiumr_file} ]]; then
		echo -e "${Error} Libsodium öňem gurnalan, täzelälimi? (Täzeleden gurmak)？[y/N]"
		read -e -p "(По умолчанию: n):" yn
		[[ -z ${yn} ]] && yn="n"
		if [[ ${yn} == [Nn] ]]; then
			echo "Ýatyrylýar..." && exit 1
		fi
	else
		echo -e "${Info} libsodium gurnalmadyk, ýükläp başla..."
	fi
	Check_Libsodium_ver
	if [[ ${release} == "centos" ]]; then
		yum update
		echo -e "${Info} бла бла бла..."
		yum -y groupinstall "Development Tools"
		echo -e "${Info} Ýüklenýär..."
		#https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}-RELEASE/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} Pakedy açylýar..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} Gurnalýar..."
		./configure --disable-maintainer-mode && make -j2 && make install
		echo /usr/local/lib > /etc/ld.so.conf.d/usr_local_lib.conf
	else
		apt-get update
		echo -e "${Info} бла бла бла..."
		apt-get install -y build-essential
		echo -e "${Info} Ýüklenýar..."
		wget  --no-check-certificate -N "https://github.com/jedisct1/libsodium/releases/download/${Libsodiumr_ver}-RELEASE/libsodium-${Libsodiumr_ver}.tar.gz"
		echo -e "${Info} Pakedy açylýar..."
		tar -xzf libsodium-${Libsodiumr_ver}.tar.gz && cd libsodium-${Libsodiumr_ver}
		echo -e "${Info} Gurnalýar..."
		./configure --disable-maintainer-mode && make -j2 && make install
	fi
	ldconfig
	cd .. && rm -rf libsodium-${Libsodiumr_ver}.tar.gz && rm -rf libsodium-${Libsodiumr_ver}
	[[ ! -e ${Libsodiumr_file} ]] && echo -e "${Error} Libsodium-y gurnap bilmedik !" && exit 1
	echo && echo -e "${Info} Libsodium-y gurnadyk !" && echo
}
# 显示 连接信息
debian_View_user_connection_info(){
	format_1=$1
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Ulanyjy tapylmady !" && exit 1
	IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |grep ":${user_port} " |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
		if [[ -z ${user_IP_1} ]]; then
			user_IP_total="0"
		else
			user_IP_total=`echo -e "${user_IP_1}"|wc -l`
			if [[ ${format_1} == "IP_address" ]]; then
				get_IP_address
			else
				user_IP=`echo -e "\n${user_IP_1}"`
			fi
		fi
		user_info_233=$(python mujson_mgr.py -l|grep -w "${user_port}"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		user_list_all=${user_list_all}"Ulanyjy: ${Green}"${user_info_233}"${Font_default} Port: ${Green}"${user_port}"${Font_default} IP sany: ${Green}"${user_IP_total}"${Font_default} Bagly ulanyjylar: ${Green}${user_IP}${Font_default}\n"
		user_IP=""
	done
	echo -e "Jemi ulanyjylar: ${Green_background_prefix} "${user_total}" ${Font_default} Jemi IP sany: ${Green_background_prefix} "${IP_total}" ${Font_default} "
	echo -e "${user_list_all}"
}
centos_View_user_connection_info(){
	format_1=$1
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Ulanyjy tapylmady !" && exit 1
	IP_total=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' | grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_IP_1=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp' |grep ":${user_port} "|grep '::ffff:' |awk '{print $5}' |awk -F ":" '{print $4}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}"`
		if [[ -z ${user_IP_1} ]]; then
			user_IP_total="0"
		else
			user_IP_total=`echo -e "${user_IP_1}"|wc -l`
			if [[ ${format_1} == "IP_address" ]]; then
				get_IP_address
			else
				user_IP=`echo -e "\n${user_IP_1}"`
			fi
		fi
		user_info_233=$(python mujson_mgr.py -l|grep -w "${user_port}"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		user_list_all=${user_list_all}"Ulanyjy: ${Green}"${user_info_233}"${Font_default} Port: ${Green}"${user_port}"${Font_default} IP sany: ${Green}"${user_IP_total}"${Font_default} Bagly ulanyjylar: ${Green}${user_IP}${Font_default}\n"
		user_IP=""
	done
	echo -e "Jemi ulanyjylar: ${Green_background_prefix} "${user_total}" ${Font_default} Jemi IP adres: ${Green_background_prefix} "${IP_total}" ${Font_default} "
	echo -e "${user_list_all}"
}
View_user_connection_info(){
	SSR_installation_status
	echo && ssr_connection_info="1"
	if [[ ${ssr_connection_info} == "1" ]]; then
		View_user_connection_info_1 ""
	elif [[ ${ssr_connection_info} == "2" ]]; then
		echo -e "${Tip} Görüldi(ipip.net)，eger-de köp IP bar bolsa, onda köp wagt alyp biler..."
		View_user_connection_info_1 "IP_address"
	else
		echo -e "${Error} Dogry nomeri saýlaň(1-2)" && exit 1
	fi
}
View_user_connection_info_1(){
	format=$1
	if [[ ${release} = "centos" ]]; then
		cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
		if [[ $? = 0 ]]; then
			debian_View_user_connection_info "$format"
		else
			centos_View_user_connection_info "$format"
		fi
	else
		debian_View_user_connection_info "$format"
	fi
}
get_IP_address(){
	#echo "user_IP_1=${user_IP_1}"
	if [[ ! -z ${user_IP_1} ]]; then
	#echo "user_IP_total=${user_IP_total}"
		for((integer_1 = ${user_IP_total}; integer_1 >= 1; integer_1--))
		do
			IP=`echo "${user_IP_1}" |sed -n "$integer_1"p`
			#echo "IP=${IP}"
			IP_address=`wget -qO- -t1 -T2 http://freeapi.ipip.net/${IP}|sed 's/\"//g;s/,//g;s/\[//g;s/\]//g'`
			#echo "IP_address=${IP_address}"
			user_IP="${user_IP}\n${IP}(${IP_address})"
			#echo "user_IP=${user_IP}"
			sleep 1s
		done
	fi
}
Modify_port(){
	List_port_user
	while true
	do
		echo -e "Üýtgetmek isleýän ulanyjyňyzyň portyny ýazyň"
		read -e -p "(По умолчанию: ýatyrmak):" ssr_port
		[[ -z "${ssr_port}" ]] && echo -e "Ýatyrylýar..." && exit 1
		Modify_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${ssr_port}"',')
		if [[ ! -z ${Modify_user} ]]; then
			break
		else
			echo -e "${Error} Dogry porty ýazyň !"
		fi
	done
}
Modify_Config(){
	SSR_installation_status
	echo && echo -e "Näme etmek isleýärsiňiz？
 ${Green}1.${Font_default}  Täze konfigurasiýa goşmak
 ${Green}2.${Font_default}  Ulanyjynyň konfigurasiýasyny pozmak
————— Ulanyjynyň konfigurasiýasyny üýtgetmek —————
 ${Green}3.${Font_default}  Ulanyjynyň parolyny üýtget
 ${Green}4.${Font_default}  Kodlama şeklini üýtget
 ${Green}5.${Font_default}  Protokoly üýtget
 ${Green}6.${Font_default}  Obfs Plugini üýtget
 ${Green}7.${Font_default}  Enjam sanyny üýtget
 ${Green}8.${Font_default}  Umumy tizlik limidini üýtget
 ${Green}9.${Font_default}  Ulanyjynyň tizlik limidini üýtget
 ${Green}10.${Font_default} Umumy trafigi üýtget
 ${Green}11.${Font_default} Gadagan portlary üýtget
 ${Green}12.${Font_default} Ähli konfigurasiýalary üýtget
————— Другое —————
 ${Green}13.${Font_default} Ulanyjynyň IP adresini üýtget
 
 ${Tip} Ulanyjynyň adyny we portyny ruçnoý uýtgediň !" && echo
	read -e -p "(По умолчанию: ýatyrmak):" ssr_modify
	[[ -z "${ssr_modify}" ]] && echo "Ýatyrylýar..." && exit 1
	if [[ ${ssr_modify} == "1" ]]; then
		Add_port_user
	elif [[ ${ssr_modify} == "2" ]]; then
		Del_port_user
	elif [[ ${ssr_modify} == "3" ]]; then
		Modify_port
		Set_config_password
		Modify_config_password
	elif [[ ${ssr_modify} == "4" ]]; then
		Modify_port
		Set_config_method
		Modify_config_method
	elif [[ ${ssr_modify} == "5" ]]; then
		Modify_port
		Set_config_protocol
		Modify_config_protocol
	elif [[ ${ssr_modify} == "6" ]]; then
		Modify_port
		Set_config_obfs
		Modify_config_obfs
	elif [[ ${ssr_modify} == "7" ]]; then
		Modify_port
		Set_config_protocol_param
		Modify_config_protocol_param
	elif [[ ${ssr_modify} == "8" ]]; then
		Modify_port
		Set_config_speed_limit_per_con
		Modify_config_speed_limit_per_con
	elif [[ ${ssr_modify} == "9" ]]; then
		Modify_port
		Set_config_speed_limit_per_user
		Modify_config_speed_limit_per_user
	elif [[ ${ssr_modify} == "10" ]]; then
		Modify_port
		Set_config_transfer
		Modify_config_transfer
	elif [[ ${ssr_modify} == "11" ]]; then
		Modify_port
		Set_config_forbid
		Modify_config_forbid
	elif [[ ${ssr_modify} == "12" ]]; then
		Modify_port
		Set_config_all "Modify"
		Modify_config_all
	elif [[ ${ssr_modify} == "13" ]]; then
		Set_user_api_server_pub_addr "Modify"
		Modify_user_api_server_pub_addr
	else
		echo -e "${Error} Dogry nomeri saýlaň(1-13)" && exit 1
	fi
}
List_port_user(){
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Ulanyjy tapylmady !" && exit 1
	user_list_all=""
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		user_username=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $2}'|sed 's/\[//g;s/\]//g')
		Get_User_transfer "${user_port}"
		transfer_enable_Used_233=$(echo $((${transfer_enable_Used_233}+${transfer_enable_Used_2_1})))
		user_list_all=${user_list_all}"Ulanyjy: ${Red} "${user_username}"${Font_default} Port: ${Yellow}"${user_port}"${Font_default} Трафик: ${Ocean}${transfer_enable_Used_2}${Font_default}\n"
	done
	Get_User_transfer_all
	echo && echo -e "=== Jemi ulanyjylar: ${Green_background_prefix} "${user_total}" ${Font_default}"
	echo -e ${user_list_all}
	echo -e "=== Ulanyjylaryň umumy trafigi: ${Green_background_prefix} ${transfer_enable_Used_233_2} ${Font_default}\n"
}
Add_port_user(){
	lalal=$1
	if [[ "$lalal" == "install" ]]; then
		match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
	else
		while true
		do
			Set_config_all
			match_port=$(python mujson_mgr.py -l|grep -w "port ${ssr_port}$")
			[[ ! -z "${match_port}" ]] && echo -e "${Error} Port [${ssr_port}] öňem ulanylýar, başga saýlaň !" && exit 1
			match_username=$(python mujson_mgr.py -l|grep -w "user \[${ssr_user}]")
			[[ ! -z "${match_username}" ]] && echo -e "${Error} Ulanyjynyň ady [${ssr_user}] уже используется, выберите другое !" && exit 1
			match_add=$(python mujson_mgr.py -a -u "${ssr_user}" -p "${ssr_port}" -k "${ssr_password}" -m "${ssr_method}" -O "${ssr_protocol}" -G "${ssr_protocol_param}" -o "${ssr_obfs}" -s "${ssr_speed_limit_per_con}" -S "${ssr_speed_limit_per_user}" -t "${ssr_transfer}" -f "${ssr_forbid}"|grep -w "add user info")
			if [[ -z "${match_add}" ]]; then
				echo -e "${Error} Ulanyjyny goşup bilmedik ${Green}[Ulanyjynyň ady: ${ssr_user} , Port: ${ssr_port}]${Font_default} "
				break
			else
				Add_iptables
				Save_iptables
				howtomakedel="addport"
				AutoDelMake
				echo -e "${Info} Ulanyjy üstünlikli goşuldy ${Green}[Ulanyjy: ${ssr_user} , Port: ${ssr_port}]${Font_default} "
				echo
				Get_User_info "${ssr_port}"
				ip=$(cat ${config_user_api_file}|grep "SERVER_PUB_ADDR = "|awk -F "[']" '{print $2}')
				ss_ssr_determine
				curl -s -X POST https://api.telegram.org/bot"$bot_api"/sendMessage -d chat_id="$tg2id" -d parse_mode=Markdown -d text="Shadowsocks (ss) acar yasaldy 🔥🚀 %0A IP: $backup_serv_id %0A ADY📝: ${ssr_user} %0A Port: ${ssr_port} %0A Ocurilyan wagty: ${deldate} %0A Acar:      ${tg_ss_link}" >> curl.tmp
				rm -r curl.tmp
				read -e -p "Ulanyjynyň nastroykasyny düzmäge dowam？[Y/n]:" addyn
				[[ -z ${addyn} ]] && addyn="y"
				if [[ ${addyn} == [Nn] ]]; then
					Get_User_info "${ssr_port}"
					View_User_info
					break
				else
					echo -e "${Info} Ulanyjynyň konfigurasiýasy üýtgedilýär..."
				fi
			fi
		done
	fi
}
Del_port_user(){
	List_port_user
	while true
	do
		echo -e "Pozmak üçin ulanyjynyň portyny giriziň"
		read -e -p "(По умолчанию: ýatyrmak):" del_user_port
		[[ -z "${del_user_port}" ]] && echo -e "Ýatyrylýar..." && exit 1
		del_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${del_user_port}"',')
		if [[ ! -z ${del_user} ]]; then
			port=${del_user_port}
			match_del=$(python mujson_mgr.py -d -p "${del_user_port}"|grep -w "delete user ")
			if [[ -z "${match_del}" ]]; then
				echo -e "${Error} Ulanyjyny pozup bilmedik ${Red}[Port: ${Ocean}${del_user_port}]${Font_default} "
				break
			else
				Del_iptables
				Save_iptables
				curl -s -X POST https://api.telegram.org/bot"$bot_api"/sendMessage -d chat_id="$tg2id" -d parse_mode=Markdown -d text="Был удален ключ Shadowsocks %0A Port: ${del_user_port} %0A Сервер: ${backup_serv_id}">> curl.tmp
				rm -r curl.tmp
				echo -e "${Info} Ulanyjyny pozduk ${Red}[Port: ${Ocean}${del_user_port}]${Font_default} "
				echo
				read -e -p "Ulanyjyny pozmaga dowam？[Y/n]:" delyn
				[[ -z ${delyn} ]] && delyn="y"
				if [[ ${delyn} == [Nn] ]]; then
					break
				else
					echo -e "${Info} Ulanyjynyň konfigurasiýasyny pozmaga dowam..."
					Del_port_user
				fi
			fi
			break
		else
			echo -e "${Error} Dogry porty saýlaň !"
		fi
	done
}
Manually_Modify_Config(){
	SSR_installation_status
	vi ${config_user_mudb_file}
	echo "ShadowsocksR-y şuwagt öçürüp ýakjakmy？[Y/n]" && echo
	read -e -p "(По умолчанию: y):" yn
	[[ -z ${yn} ]] && yn="y"
	if [[ ${yn} == [Yy] ]]; then
		Restart_SSR
	fi
}
Clear_transfer(){
	SSR_installation_status
	echo && echo -e "Näme etmek isleýärsiňiz？
 ${Green}1.${Font_default}  Bir ulanyjy tarapyndan ulanylan trafigi poz
 ${Green}2.${Font_default}  Ähli ulanyjylaryň trafiklerini poz
 ${Green}3.${Font_default}  Ulanyjy trafiginiň awto pozulmagyny işlet
 ${Green}4.${Font_default}  Ulanyjy trafiginiň awto pozulmagyny duruz
 ${Green}5.${Font_default}  Ulanyjy trafiginiň awto pozulmagynynyň wagtyny üýtget" && echo
	read -e -p "(По умолчанию: Ýatyrmak):" ssr_modify
	[[ -z "${ssr_modify}" ]] && echo "Ýatyrylýar..." && exit 1
	if [[ ${ssr_modify} == "1" ]]; then
		Clear_transfer_one
	elif [[ ${ssr_modify} == "2" ]]; then
		echo "Siz hakykatdanam ähli ulanyjylaryň trafiklerini pozmak isleýaňizmi？[y/N]" && echo
		read -e -p "(По умолчанию: n):" yn
		[[ -z ${yn} ]] && yn="n"
		if [[ ${yn} == [Yy] ]]; then
			Clear_transfer_all
		else
			echo "Ýatyrylýar..."
		fi
	elif [[ ${ssr_modify} == "3" ]]; then
		check_crontab
		Set_crontab
		Clear_transfer_all_cron_start
	elif [[ ${ssr_modify} == "4" ]]; then
		check_crontab
		Clear_transfer_all_cron_stop
	elif [[ ${ssr_modify} == "5" ]]; then
		check_crontab
		Clear_transfer_all_cron_modify
	else
		echo -e "${Error} Dogry nomeri saýlaň(1-5)" && exit 1
	fi
}
Clear_transfer_one(){
	List_port_user
	while true
	do
		echo -e "Trafigini pozmaly ulanyjynyň portyny giriziň"
		read -e -p "(По умолчанию: Ýatyr):" Clear_transfer_user_port
		[[ -z "${Clear_transfer_user_port}" ]] && echo -e "Ýatyrylýar..." && exit 1
		Clear_transfer_user=$(cat "${config_user_mudb_file}"|grep '"port": '"${Clear_transfer_user_port}"',')
		if [[ ! -z ${Clear_transfer_user} ]]; then
			match_clear=$(python mujson_mgr.py -c -p "${Clear_transfer_user_port}"|grep -w "clear user ")
			if [[ -z "${match_clear}" ]]; then
				echo -e "${Error} Ulanyjynyň trafigini pozup bilmedik! ${Green}[Port: ${Clear_transfer_user_port}]${Font_default} "
			else
				echo -e "${Info} Ulanyjynyň trafigini pozduk! ${Green}[Port: ${Clear_transfer_user_port}]${Font_default} "
			fi
			break
		else
			echo -e "${Error} Dogry porty saýlaň !"
		fi
	done
}
Clear_transfer_all(){
	cd "${ssr_folder}"
	user_info=$(python mujson_mgr.py -l)
	user_total=$(echo "${user_info}"|wc -l)
	[[ -z ${user_info} ]] && echo -e "${Error} Ulanyjy tapylmady !" && exit 1
	for((integer = 1; integer <= ${user_total}; integer++))
	do
		user_port=$(echo "${user_info}"|sed -n "${integer}p"|awk '{print $4}')
		match_clear=$(python mujson_mgr.py -c -p "${user_port}"|grep -w "clear user ")
		if [[ -z "${match_clear}" ]]; then
			echo -e "${Error} Ulanyjynyň trafigini pozup bilmedik!  ${Green}[Port: ${user_port}]${Font_default} "
		else
			echo -e "${Info} Ulanyjynyň trafigini pozduk! ${Green}[Port: ${user_port}]${Font_default} "
		fi
	done
	echo -e "${Info} Ähli ulanyjylaryň trafikleri pozuldy !"
}
Clear_transfer_all_cron_start(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh/d" "$file/crontab.bak"
	echo -e "\n${Crontab_time} /bin/bash $file/ssrmu.sh clearall" >> "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} Ulanyjynyň traffiginiň yzygiderli pozulmagy işlänok !" && exit 1
	else
		echo -e "${Info} Ulanyjynyň traffiginiň yzygiderli pozulmagy işledildi !"
	fi
}
Clear_transfer_all_cron_stop(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh/d" "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} Ulanyjynyň traffiginiň awto pozulmagyny duruzup bilmedik !" && exit 1
	else
		echo -e "${Info} Ulanyjynyň traffiginiň awto pozulmagyny duruzdyk !"
	fi
}
Clear_transfer_all_cron_modify(){
	Set_crontab
	Clear_transfer_all_cron_stop
	Clear_transfer_all_cron_start
}
Set_crontab(){
		echo -e "Введите временный интервал для очистки трафика
 === Описание формата ===
 * * * * * Минуты, часы, дни, месяцы, недели
 ${Green} 0 2 1 * * ${Font_default} Означает каждый месяц 1ого числа в 2 часа
 ${Green} 0 2 15 * * ${Font_default} Означает каждый месяц 15ого числа в 2 часа
 ${Green} 0 2 */7 * * ${Font_default} Каждые 7 дней в 2 часа
 ${Green} 0 2 * * 0 ${Font_default} Каждое воскресенье
 ${Green} 0 2 * * 3 ${Font_default} Каждую среду" && echo
	read -e -p "(По умолчанию: 0 2 1 * * Тоесть каждое 1ое число месяца в 2 часа):" Crontab_time
	[[ -z "${Crontab_time}" ]] && Crontab_time="0 2 1 * *"
}
Start_SSR(){
	SSR_installation_status
	check_pid
	[[ ! -z ${PID} ]] && echo -e "${Error} ShadowsocksR işledilen !" && exit 1
	/etc/init.d/ssrmu start
}
Stop_SSR(){
	SSR_installation_status
	check_pid
	[[ -z ${PID} ]] && echo -e "${Error} ShadowsocksR işledilmedik !" && exit 1
	/etc/init.d/ssrmu stop
}
Restart_SSR(){
	SSR_installation_status
	check_pid
	[[ ! -z ${PID} ]] && /etc/init.d/ssrmu stop
	/etc/init.d/ssrmu start
}
View_Log(){
	SSR_installation_status
	[[ ! -e ${ssr_log_file} ]] && echo -e "${Error} ShadowsocksR log-y ýok !" && exit 1
	echo && echo -e "${Tip} Нажмите ${Red}Ctrl+C${Font_default} для остановки просмотра лога" && echo -e "Если вам нужен полный лог, то напишите ${Red}cat ${ssr_log_file}${Font_default} 。" && echo
	tail -f ${ssr_log_file}
}
# 锐速
Configure_Server_Speeder(){
	echo && echo -e "Näme etmek isleýärsiňiz？
 ${Green}1.${Font_default} Sharp Speed gurnamak
 ${Green}2.${Font_default} Sharp Speed pozmak
————————
 ${Green}3.${Font_default} Sharp Speed işletmek
 ${Green}4.${Font_default} Sharp Speed duruzmak
 ${Green}5.${Font_default} Sharp Speed öçürüp ýakmak
 ${Green}6.${Font_default} Sharp Speed ýagdaýyny görmek
 
 Заметка: LotServer bilen Rui Su bir wagtda gurnalyp bilmez！" && echo
	read -e -p "(По умолчанию: Ýatyr):" server_speeder_num
	[[ -z "${server_speeder_num}" ]] && echo "Ýatyrylýar..." && exit 1
	if [[ ${server_speeder_num} == "1" ]]; then
		Install_ServerSpeeder
	elif [[ ${server_speeder_num} == "2" ]]; then
		Server_Speeder_installation_status
		Uninstall_ServerSpeeder
	elif [[ ${server_speeder_num} == "3" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} start
		${Server_Speeder_file} status
	elif [[ ${server_speeder_num} == "4" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} stop
	elif [[ ${server_speeder_num} == "5" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} restart
		${Server_Speeder_file} status
	elif [[ ${server_speeder_num} == "6" ]]; then
		Server_Speeder_installation_status
		${Server_Speeder_file} status
	else
		echo -e "${Error} Dogry nomeri saýlaň(1-6)" && exit 1
	fi
}
Install_ServerSpeeder(){
	[[ -e ${Server_Speeder_file} ]] && echo -e "${Error} Server Speeder öňem gurnalan !" && exit 1
	#借用91yun.rog的开心版锐速
	wget --no-check-certificate -qO /tmp/serverspeeder.sh https://raw.githubusercontent.com/91yun/serverspeeder/master/serverspeeder.sh
	[[ ! -e "/tmp/serverspeeder.sh" ]] && echo -e "${Error} Rui Su skriptini gurnap bilmedik !" && exit 1
	bash /tmp/serverspeeder.sh
	sleep 2s
	PID=`ps -ef |grep -v grep |grep "serverspeeder" |awk '{print $2}'`
	if [[ ! -z ${PID} ]]; then
		rm -rf /tmp/serverspeeder.sh
		rm -rf /tmp/91yunserverspeeder
		rm -rf /tmp/91yunserverspeeder.tar.gz
		echo -e "${Info} Server Speeder üstünlikli gurnaldy !" && exit 1
	else
		echo -e "${Error} Server Speeder-i gurnap bilmedik !" && exit 1
	fi
}
Uninstall_ServerSpeeder(){
	echo "Server Speeder pozmak isleýänizmi？[y/N]" && echo
	read -e -p "(По умолчанию: n):" unyn
	[[ -z ${unyn} ]] && echo && echo "Ýatyrylýar..." && exit 1
	if [[ ${unyn} == [Yy] ]]; then
		chattr -i /serverspeeder/etc/apx*
		/serverspeeder/bin/serverSpeeder.sh uninstall -f
		echo && echo "Server Speeder üstünlikli pozuldy !" && echo
	fi
}
# LotServer
Configure_LotServer(){
	echo && echo -e "Näme etmek isleýäňiz？
 ${Green}1.${Font_default} LotServer-i gurnamak
 ${Green}2.${Font_default} LotServer-i pozmak
————————
 ${Green}3.${Font_default} LotServer-i işletmek
 ${Green}4.${Font_default} LotServer-i duruzmak
 ${Green}5.${Font_default} LotServer-i öçürüp ýakmak
 ${Green}6.${Font_default} LotServer-iň ýagdaýyny görmek
 
 Заметка: LotServer и Rui Su не могут быть установлены в одно и тоже время！" && echo
	read -e -p "(По умолчанию: Ýatyr):" lotserver_num
	[[ -z "${lotserver_num}" ]] && echo "Ýatyr..." && exit 1
	if [[ ${lotserver_num} == "1" ]]; then
		Install_LotServer
	elif [[ ${lotserver_num} == "2" ]]; then
		LotServer_installation_status
		Uninstall_LotServer
	elif [[ ${lotserver_num} == "3" ]]; then
		LotServer_installation_status
		${LotServer_file} start
		${LotServer_file} status
	elif [[ ${lotserver_num} == "4" ]]; then
		LotServer_installation_status
		${LotServer_file} stop
	elif [[ ${lotserver_num} == "5" ]]; then
		LotServer_installation_status
		${LotServer_file} restart
		${LotServer_file} status
	elif [[ ${lotserver_num} == "6" ]]; then
		LotServer_installation_status
		${LotServer_file} status
	else
		echo -e "${Error} Dogry nomeri saýlaň(1-6)" && exit 1
	fi
}
Install_LotServer(){
	[[ -e ${LotServer_file} ]] && echo -e "${Error} LotServer уже установлен !" && exit 1
	#Github: https://github.com/0oVicero0/serverSpeeder_Install
	wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh"
	[[ ! -e "/tmp/appex.sh" ]] && echo -e "${Error} Загрузка скрипта LotServer провалена !" && exit 1
	bash /tmp/appex.sh 'install'
	sleep 2s
	PID=`ps -ef |grep -v grep |grep "appex" |awk '{print $2}'`
	if [[ ! -z ${PID} ]]; then
		echo -e "${Info} LotServer успешно установлен !" && exit 1
	else
		echo -e "${Error} Не удалось установить LotServer  !" && exit 1
	fi
}
Uninstall_LotServer(){
	echo "Вы уверены что хотите удалить LotServer？[y/N]" && echo
	read -e -p "(По умолчанию: n):" unyn
	[[ -z ${unyn} ]] && echo && echo "Ýatyr..." && exit 1
	if [[ ${unyn} == [Yy] ]]; then
		wget --no-check-certificate -qO /tmp/appex.sh "https://raw.githubusercontent.com/0oVicero0/serverSpeeder_Install/master/appex.sh" && bash /tmp/appex.sh 'uninstall'
		echo && echo "LotServer успешно деинсталлирован !" && echo
	fi
}
# BBR
Configure_BBR(){
	echo && echo -e "  Что будем делать？
	
 ${Green}1.${Font_default} Установить BBR
————————
 ${Green}2.${Font_default} Запустить BBR
 ${Green}3.${Font_default} Остановить BBR
 ${Green}4.${Font_default} Просмотреть статус BBR" && echo
echo -e "${Green} [ВНИМАТЕЛЬНО ПРОЧИТАЙТЕ ТЕКСТ СНИЗУ!!!] ${Font_default}
1. Для успешной установки BBR нужно заменить ядро, что может привести к поломке сервера
2. OpenVZ и Docker не поддерживают данную функцию, нужен Debian/Ubuntu!
3. Если у вас система Debian, то при выборе [ При остановке деинсталлирования ядра ] ，то выберите ${Green} NO ${Font_default}" && echo
	read -e -p "(По умолчанию: Ýatyr):" bbr_num
	[[ -z "${bbr_num}" ]] && echo "Ýatyrylýar..." && exit 1
	if [[ ${bbr_num} == "1" ]]; then
		Install_BBR
	elif [[ ${bbr_num} == "2" ]]; then
		Start_BBR
	elif [[ ${bbr_num} == "3" ]]; then
		Stop_BBR
	elif [[ ${bbr_num} == "4" ]]; then
		Status_BBR
	else
		echo -e "${Error} Dogry nomeri saýlaň(1-4)" && exit 1
	fi
}
Install_BBR(){
	[[ ${release} = "centos" ]] && echo -e "${Error} Скрипт не поддерживает установку BBR на CentOS !" && exit 1
	BBR_installation_status
	bash "${BBR_file}"
}
Start_BBR(){
	BBR_installation_status
	bash "${BBR_file}" start
}
Stop_BBR(){
	BBR_installation_status
	bash "${BBR_file}" stop
}
Status_BBR(){
	BBR_installation_status
	bash "${BBR_file}" status
}
# 其他功能
Other_functions(){
	echo && echo -e "  Что будем делать？
	
  ${Green}1.${Font_default} Настроить BBR
  ${Green}2.${Font_default} Настроить Sharp Speed(ServerSpeeder)
  ${Green}3.${Font_default} Настроить LotServer(дочерняя программа Rui Speed)
  ${Tip} Rui Su/LotServer/BBR не поддерживают OpenVZ！
  ${Tip} Sharp Speed и LotServer не могут быть установлены вместе！
————————————
  ${Green}4.${Font_default} 一Блокировка BT/PT/SPAM в один клик (iptables)
  ${Green}5.${Font_default} 一Разблокировка BT/PT/SPAM в один клик (iptables)
————————————
  ${Green}6.${Font_default} Изменить тип вывода лога ShadowsocksR
  —— Подсказка：SSR по умолчанию выводит только ошибочные логи. Лог можно изменить на более детализированный。
  ${Green}7.${Font_default} Монитор текущего статуса ShadowsocksR
  —— Подсказка： Эта функция очень полезна если SSR часто выключается. Каждую минуту скрипт будеть проверять статус ShadowsocksR, и если он выключен, включать его" && echo
	read -e -p "(По умолчанию: Ýatyr):" other_num
	[[ -z "${other_num}" ]] && echo "Ýatyrylýar..." && exit 1
	if [[ ${other_num} == "1" ]]; then
		Configure_BBR
	elif [[ ${other_num} == "2" ]]; then
		Configure_Server_Speeder
	elif [[ ${other_num} == "3" ]]; then
		Configure_LotServer
	elif [[ ${other_num} == "4" ]]; then
		BanBTPTSPAM
	elif [[ ${other_num} == "5" ]]; then
		UnBanBTPTSPAM
	elif [[ ${other_num} == "6" ]]; then
		Set_config_connect_verbose_info
	elif [[ ${other_num} == "7" ]]; then
		Set_crontab_monitor_ssr
	else
		echo -e "${Error} Dogry nomeri saýlaň [1-7]" && exit 1
	fi
}
# 封禁 BT PT SPAM
BanBTPTSPAM(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/ban_iptables.sh && chmod +x ban_iptables.sh && bash ban_iptables.sh banall
	rm -rf ban_iptables.sh
}
# 解封 BT PT SPAM
UnBanBTPTSPAM(){
	wget -N --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/ban_iptables.sh && chmod +x ban_iptables.sh && bash ban_iptables.sh unbanall
	rm -rf ban_iptables.sh
}
Set_config_connect_verbose_info(){
	SSR_installation_status
	[[ ! -e ${jq_file} ]] && echo -e "${Error} Отсутствует парсер JQ !" && exit 1
	connect_verbose_info=`${jq_file} '.connect_verbose_info' ${config_user_file}`
	if [[ ${connect_verbose_info} = "0" ]]; then
		echo && echo -e "Текущий режим логирования: ${Green}простой（только ошибки）${Font_default}" && echo
		echo -e "Вы уверены, что хотите сменить его на  ${Green}детализированный(Детальный лог соединений + ошибки)${Font_default}？[y/N]"
		read -e -p "(По умолчанию: n):" connect_verbose_info_ny
		[[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
		if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
			ssr_connect_verbose_info="1"
			Modify_config_connect_verbose_info
			Restart_SSR
		else
			echo && echo "	Ýatyr..." && echo
		fi
	else
		echo && echo -e "Текущий режим логирования: ${Green}детализированный(Детальный лог соединений + ошибки)${Font_default}" && echo
		echo -e "Вы уверены, что хотите сменить его на  ${Green}простой（только ошибки）${Font_default}？[y/N]"
		read -e -p "(По умолчанию: n):" connect_verbose_info_ny
		[[ -z "${connect_verbose_info_ny}" ]] && connect_verbose_info_ny="n"
		if [[ ${connect_verbose_info_ny} == [Yy] ]]; then
			ssr_connect_verbose_info="0"
			Modify_config_connect_verbose_info
			Restart_SSR
		else
			echo && echo "	Ýatyr..." && echo
		fi
	fi
}
Set_crontab_monitor_ssr(){
	SSR_installation_status
	crontab_monitor_ssr_status=$(crontab -l|grep "ssrmu.sh monitor")
	if [[ -z "${crontab_monitor_ssr_status}" ]]; then
		echo && echo -e "Текущий статус мониторинга: ${Green}выключен${Font_default}" && echo
		echo -e "Вы уверены что хотите включить ${Green}функцию мониторинга ShadowsocksR${Font_default}？(При отключении SSR, он будет запущен автоматически)[Y/n]"
		read -e -p "(По умолчанию: y):" crontab_monitor_ssr_status_ny
		[[ -z "${crontab_monitor_ssr_status_ny}" ]] && crontab_monitor_ssr_status_ny="y"
		if [[ ${crontab_monitor_ssr_status_ny} == [Yy] ]]; then
			crontab_monitor_ssr_cron_start
		else
			echo && echo "	Ýatyrylýar..." && echo
		fi
	else
		echo && echo -e "Текущий статус мониторинга: ${Green}включен${Font_default}" && echo
		echo -e "Вы уверены что хотите выключить ${Green}функцию мониторинга ShadowsocksR${Font_default}？(При отключении SSR, он будет запущен автоматически)[y/N]"
		read -e -p "(По умолчанию: n):" crontab_monitor_ssr_status_ny
		[[ -z "${crontab_monitor_ssr_status_ny}" ]] && crontab_monitor_ssr_status_ny="n"
		if [[ ${crontab_monitor_ssr_status_ny} == [Yy] ]]; then
			crontab_monitor_ssr_cron_stop
		else
			echo && echo "	Ýatyrylýar..." && echo
		fi
	fi
}
crontab_monitor_ssr(){
	SSR_installation_status
	check_pid
	if [[ -z ${PID} ]]; then
		echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] Замечено что SSR не запущен, запускаю..." | tee -a ${ssr_log_file}
		/etc/init.d/ssrmu start
		sleep 1s
		check_pid
		if [[ -z ${PID} ]]; then
			echo -e "${Error} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] ShadowsocksR не удалось запустить..." | tee -a ${ssr_log_file} && exit 1
		else
			echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] ShadowsocksR успешно установлен..." | tee -a ${ssr_log_file} && exit 1
		fi
	else
		echo -e "${Info} [$(date "+%Y-%m-%d %H:%M:%S %u %Z")] ShadowsocksR успешно работает..." exit 0
	fi
}
crontab_monitor_ssr_cron_start(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh monitor/d" "$file/crontab.bak"
	echo -e "\n* * * * * /bin/bash $file/ssrmu.sh monitor" >> "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh monitor")
	if [[ -z ${cron_config} ]]; then
		echo -e "${Error} Не удалось запустить функцию мониторинга ShadowsocksR  !" && exit 1
	else
		echo -e "${Info} Функция мониторинга ShadowsocksR успешно запущена !"
	fi
}
crontab_monitor_ssr_cron_stop(){
	crontab -l > "$file/crontab.bak"
	sed -i "/ssrmu.sh monitor/d" "$file/crontab.bak"
	crontab "$file/crontab.bak"
	rm -r "$file/crontab.bak"
	cron_config=$(crontab -l | grep "ssrmu.sh monitor")
	if [[ ! -z ${cron_config} ]]; then
		echo -e "${Error} Не удалось остановить функцию моинторинга сервера ShadowsocksR !" && exit 1
	else
		echo -e "${Info} Функция мониторинга сервера ShadowsocksR успешно остановлена !"
	fi
}
Update_Shell(){
	sh_new_ver=$(wget --no-check-certificate -qO- -t1 -T3 "https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/ssrmu.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1) && sh_new_type="github"
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} Не удается подключиться к Github !" && exit 0
	if [[ -e "/etc/init.d/ssrmu" ]]; then
		rm -rf /etc/init.d/ssrmu
		Service_SSR
	fi
	cd "${file}"
	wget -N --no-check-certificate "https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/ssrmu.sh" && chmod +x ssrmu.sh
	echo -e "Скрипт успешно обновлен до версии[ ${sh_new_ver} ] !(Так как обновление - перезапись, то далее могут выйти ошибки, просто инорируйте их)" && exit 0
}
# 显示 菜单状态
menu_status(){
	if [[ -e ${ssr_folder} ]]; then
		check_pid
		if [[ ! -z "${PID}" ]]; then
			echo -e "${Red}Ýagdaýy: ${Green}gurnalan${Font_default} we ${Green}işledilen${Font_default}"
		else
			echo -e "${Red}Ýagdaýy: ${Green}gurnalan${Font_default} ýöne ${Red}işledilmedik${Font_default}"
		fi
		cd "${ssr_folder}"
	else
		echo -e "${Red}Ýagdaýy: ${Red}işledilmedik${Font_default}"
	fi
}
Server_IP_Checker(){
	 echo -e "Häzirki serweriň IP-sy = $(curl "ifconfig.me") " && echo
}
check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && [[ ${release} != "centos" ]] && echo -e "${Error} 本脚本不支持当前系统 ${release} !" && exit 1
action=$1
if [[ "${action}" == "clearall" ]]; then
	Clear_transfer_all
elif [[ "${action}" == "autobak" ]]; then
	Autobak
elif [[ "${action}" == "monitor" ]]; then
	crontab_monitor_ssr
else
	useronline=`netstat -anp |grep 'ESTABLISHED' |grep 'python' |grep 'tcp6' |awk '{print $5}' |awk -F ":" '{print $1}' |sort -u |grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" |wc -l`
	clear
	echo -e " 
${Purple}|————————————————————————————————————|${Font_default}
${Purple}|${Font_default}${Purple}———————————${Font_default} Maglumatlar ${Purple}————————————${Font_default}${Purple}|${Font_default}
${Purple}|${Font_default}${Red}Düzen:${Yellow} lemon ${Purple}                            ${Font_default}${Purple}|${Font_default}
${Purple}|${Font_default}${Red}Telegram:${Yellow} Lemon ${Purple}                        ${Font_default}${Purple}|${Font_default}
${Purple}|${Font_default}${Red}Sene: ${Yellow}[$(date +"%d-%m-%Y")]${Purple}                  ${Font_default}${Purple}|${Font_default}
${Purple}|${Font_default}$(menu_status)${Purple}        ${Font_default}${Purple}|${Font_default}
${Purple}|${Font_default}${Red}Skriptiň versiýasy: ${Yellow}v${sh_ver}${Font_default}                 ${Purple}|${Font_default}
${Purple}|${Font_default}${Red}Online ulanyjylar: ${Yellow}${useronline}${Font_default}               ${Purple}|${Font_default}
${Purple}|————————————————————————————————————|${Font_default}
${Purple}|${Font_default}${Purple}—————————${Font_default} Skript-i gurnamak ${Purple}——————————${Font_default}${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}1.${Font_default} ${Red}Shadowsocks-y gurnamak${Font_default}           ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}2.${Font_default} ${Red}Shadowsocks-y pozmak${Font_default}             ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}————————${Font_default} Açarlary dolandyrmak ${Purple}————————${Font_default}${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}3.${Font_default} ${Red}Açar ýasa${Font_default}                        ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}4.${Font_default} ${Red}Açary poz${Font_default}                        ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}5.${Font_default} ${Red}Klentlar barada maglumatlar${Font_default}      ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}6.${Font_default} ${Red}Online ulanyjylaryň IP-lary${Font_default}      ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}——————————${Font_default} Maglumat Bazasy ${Purple}———————————${Font_default}${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}7.${Font_default} ${Red}Bazany buluda ýükle${Font_default}              ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}8.${Font_default} ${Red}Bazany özüňe ýükle${Font_default}               ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}9.${Font_default} ${Red}Awto_Bekup sazlamalary${Font_default}           ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}—————————${Font_default} Skripti dolandyrmak ${Purple}————————${Font_default}${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}10.${Font_default} ${Red}Shadowsocksy işlet${Font_default}              ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}11.${Font_default} ${Red}Shadowsocksy öçür${Font_default}               ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}12.${Font_default} ${Red}Shadowsocksy öçürüp ýak${Font_default}         ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}13.${Font_default} ${Red}Domainy üýtget${Font_default}                  ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}14.${Font_default} ${Red}Awto-Pozmak menýusy${Font_default}             ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}15.${Font_default} ${Red}Goşmaça${Font_default}                         ${Purple}|${Font_default}
${Purple}|${Font_default}${Purple}16.${Font_default} ${Red}Çykyş${Font_default}                           ${Purple}|${Font_default}
${Purple}|————————————————————————————————————|${Font_default} 
	 " 
	cd "${ssr_folder}"
	read -e -p "Name edeli? [1-16]:" num
	case "$num" in
		1)
		Install_SSR
		;;
		2)
		Parol
		Uninstall_SSR
		;;
		3)
		Add_port_user
		;;
		4)
		Del_port_user
		;;
		5)
		View_User
		;;
		6)
		View_user_connection_info
		;;
		7)
		Upload_DB
		;;
		8)
		Download_DB
		;;
		9)
		AutobakMenu
		;;
		10)
		Start_SSR
		;;
		11)
		Stop_SSR
		;;
		12)
		Restart_SSR
		;;
		13)
		Set_user_api_server_pub_addr "Modify"
		Modify_user_api_server_pub_addr
		DomainChange
		;;
		14)
		AutoDelMenu
		;;
		15)
		Other_functions
		;;
		16)
		ScriptExit
		;;
		*)
		echo -e "${Error} ${Red}Dogry nomeri saýlaň [1-15]: ${Font_default}"
		;;
	esac
	fi