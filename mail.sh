#!/bin/bash
default_timeout=1
default_mailserver="mail.mediaster.cz"
default_interface="eth0"
default_addip="n"
default_sender_ip="81.0.208.20"
default_wapi_url="http://emailing.mediasun.cz/nejaky-skript.php"
default_wapi_pass="google123"

echo -n "Zadej nazev serveru (napr. postster): "
read server
if [ -z "${server}" ]; then
    echo "Neni vyplnen nazev serveru."
    exit 1
fi


wapi_enabled=1
wapi_pass=""
echo "Aktivovat WAPI? [Y/n]"
read wapi_ans
if [ "${wapi_ans}" == 'n' -o "${wapi_ans}" == 'N' ]; then
    echo "WAPI deaktivovano."
    wapi_enabled=0
else
    echo "WAPI aktivovano. URL pro zasladni pozadavku: ${default_wapi_url}"
    echo "Zadejte heslo k wapi [$default_wapi_pass]: "
    read wapi_pass
    if [ -z "${wapi_pass}" ]; then
        wapi_pass="${default_wapi_pass}"
    fi
fi

echo -ne $server > /etc/hostname
echo -ne "" > /etc/motd
apt-get -y remove man-db install-info vim-tiny nano
apt-get -y install curl
passwd

cat << EOF >> /etc/sysctl.conf
    net.ipv6.conf.all.disable_ipv6 = 1
    net.ipv6.conf.default.disable_ipv6 = 1
    net.ipv6.conf.lo.disable_ipv6 = 1
    net.ipv6.bindv6only = 1
EOF
sysctl -p

# mail instalator
echo  "Spustil si instalacni skript mailserveru."
echo -n "Vypln prosim domenu mailserveru [neco.tld]: "
read domain
if [ -z "${domain}" ]; then
    echo "Chybne vyplnena domena - ukoncuji instalator"
    exit
fi

echo -n "Vypln prosim ip adresu odesilatele [${default_sender_ip}]: "
read sender
if [ -z "${sender}" ]; then
    sender=$default_sender_ip
    echo "Pouzita vychozi hodnota: ${default_sender_ip}"
fi

echo -n "Pocet sekund cekani na odeslani dalsi zpravy [${default_timeout}]: "
read timeout
if [ -z "${timeout}" ]; then
    timeout=$default_timeout
    echo "Pouzita vychozi hodnota: ${default_timeout}"
fi

echo -n "Mailserver pro prijimani FBL, Unsubscribe atp [${default_mailserver}]: "
read mailmx
if [ -z "${mailmx}" ]; then
    mailmx=$default_mailserver
    echo "Pouzita vychozi hodnota: [${default_mailserver}]"
fi

echo "dostupne interface:"
ifconfig -a | sed 's/[ \t].*//;/^$/d'
echo -n "iface serveru [${default_interface}]:"
read iface
if [ -z "${iface}" ]; then
    iface=$default_interface
    echo "Pouzita vychozi hodnota: [${default_interface}]"
fi
IP_ADRESA=`ifconfig ${iface} | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}'`
echo "mailserver ma nasledujici IP adresu: ${IP_ADRESA}"
spojeni="1"

echo -n "chcete pridat dalsi IP [y/N]:"
read addip
if [ -z "${addip}" ]; then
    addip=$default_addip
    echo "Pouzita vychozi hodnota: [${default_addip}]"
fi
ano="y"
if [ "$addip" = "$ano" ]; then
    echo -n "vyplnte prosim interface [eth0]: "
    read addip_interface
    echo -n "zadejte pocatectni ip adresu: "
    read addip_firstip
    echo -n "zadejte pocet ip adres: "
    read addip_count
    odecti="1"
    SEQUENCE="$((addip_count - odecti))"
    pricti="1"
    SHLAVNIIP="$((addip_count + pricti))"
    spojeni="$((addip_count + pricti))"
    IPKA1=`echo $addip_firstip |  cut -d "." -f 1`
    IPKA2=`echo $addip_firstip |  cut -d "." -f 2`
    IPKA3=`echo $addip_firstip |  cut -d "." -f 3`
    IPKA4=`echo $addip_firstip |  cut -d "." -f 4`
    echo "povoluji vice IP v jadre"
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    sysctl -p
    echo "vytvarim konfiguracni soubor /etc/multipleip.sh"
    echo "modprobe dummy" > /etc/multipleip.sh
    echo "iptables -t nat -I POSTROUTING -m state --state NEW -p tcp --dport 25 -o ${iface} -m statistic --mode nth --every ${SHLAVNIIP} --packet 0 -j SNAT --to-source ${IP_ADRESA}" >> /etc/multipleip.sh
    for i in $(seq 0 $SEQUENCE); do
        DOCASNE="$((IPKA4 + i))"
        DOCASNECISLO="$((pricti + i))"
        echo "NASTAVUJI IP ${IPKA1}.${IPKA2}.${IPKA3}.${DOCASNE}"
        echo "ifconfig ${addip_interface}:${DOCASNECISLO} ${IPKA1}.${IPKA2}.${IPKA3}.${DOCASNE} netmask 255.255.255.255" >> /etc/multipleip.sh
        echo "iptables -t nat -I POSTROUTING -m state --state NEW -p tcp --dport 25 -o ${iface} -m statistic --mode nth --every ${SHLAVNIIP} --packet ${DOCASNECISLO} -j SNAT --to-source ${IPKA1}.${IPKA2}.${IPKA3}.${DOCASNE}" >> /etc/multipleip.sh
    done

    chmod +x /etc/multipleip.sh
    echo "#!/bin/sh -e" > /etc/rc.local
    echo "/etc/multipleip.sh" >> /etc/rc.local
    echo "exit 0" >> /etc/rc.local
    chmod +x /etc/rc.local
    /etc/multipleip.sh
fi

echo 'deb http://ftp.debian.org/debian jessie-backports main' | tee /etc/apt/sources.list.d/backports.list
#aktualizace baliku na OS
apt-get update
apt update
#instalovani zakladnich baliku
apt-get -y install python-certbot-nginx -t jessie-backports
apt install -y fcgiwrap
systemctl enable fcgiwrap
/etc/init.d/fcgiwrap start

apt-get -y install opendkim opendkim-tools nginx perl sudo php5-fpm
DEBIAN_FRONTEND=noninteractive apt-get -y install postfix

/etc/init.d/nginx stop
letsencrypt certonly --agree-tos --standalone -d mail.${domain} -m info@"${domain}"
letsencrypt certonly --agree-tos --standalone -d ${domain} -m info@"${domain}"
/etc/init.d/nginx restart


echo "%www-data ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

echo "# generated by mailconfig skript" > /etc/opendkim.conf
echo "AutoRestart             Yes" >> /etc/opendkim.conf
echo "AutoRestartRate         10/1h" >> /etc/opendkim.conf
echo "UMask                   002" >> /etc/opendkim.conf
echo "Syslog                  yes" >> /etc/opendkim.conf
echo "SyslogSuccess           Yes" >> /etc/opendkim.conf
echo "LogWhy                  Yes" >> /etc/opendkim.conf
echo "Canonicalization        relaxed/simple" >> /etc/opendkim.conf
echo "ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts" >> /etc/opendkim.conf
echo "InternalHosts           refile:/etc/opendkim/TrustedHosts" >> /etc/opendkim.conf
echo "KeyTable                refile:/etc/opendkim/KeyTable" >> /etc/opendkim.conf
echo "SigningTable            refile:/etc/opendkim/SigningTable" >> /etc/opendkim.conf
echo "Mode                    sv" >> /etc/opendkim.conf
echo "PidFile                 /var/run/opendkim/opendkim.pid" >> /etc/opendkim.conf
echo "SignatureAlgorithm      rsa-sha256" >> /etc/opendkim.conf
echo "UserID                  opendkim:opendkim" >> /etc/opendkim.conf
echo "Socket                  inet:12301@localhost" >> /etc/opendkim.conf

echo "SOCKET=\"inet:12301@localhost\"" >> /etc/default/opendkim

echo "/^Received: .*/     IGNORE" >> /etc/postfix/header_checks
echo "/^X-Originating-IP:/    IGNORE" >> /etc/postfix/header_checks

chmod 777 /etc/postfix/header_checks

cp  /etc/postfix/main.cf /etc/postfix/main.cf.$$
cat << "EOF" > /etc/postfix/main.cf
smtpd_banner = $myhostname ESMTP $mail_name
biff = no
readme_directory = no
EOF

echo "milter_protocol = 2"                              >> /etc/postfix/main.cf
echo "milter_default_action = accept"                   >> /etc/postfix/main.cf
echo "smtpd_milters = inet:127.0.0.1:12301"             >> /etc/postfix/main.cf
echo "non_smtpd_milters = inet:127.0.0.1:12301"         >> /etc/postfix/main.cf
echo "header_checks = regexp:/etc/postfix/header_checks" >> /etc/postfix/main.cf
echo "relay_domains = ${domain}"                        >> /etc/postfix/main.cf

postconf -e "myhostname = ${domain}"
postconf -e "mynetworks = 127.0.0.1/32 ${sender}/32"
postconf -e "smtp_destination_concurrency_limit = ${spojeni}"
postconf -e "smtp_destination_rate_delay = ${timeout}s"
postconf -e "smtp_extra_recipient_limit = 10"
postconf -e "smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination"

postconf -e "smtpd_tls_cert_file = /etc/letsencrypt/live/${domain}/fullchain.pem"
postconf -e "smtpd_tls_key_file = /etc/letsencrypt/live/${domain}/privkey.pem"
postconf -e 'smtpd_use_tls=yes'

postconf -e 'smtp_use_tls = yes'
postconf -e 'smtp_tls_security_level = may'

postconf -e 'smtp_tls_mandatory_ciphers=high'
postconf -e 'smtp_tls_mandatory_protocols = !SSLv2, !SSLv3'
postconf -e 'smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache'
postconf -e 'smtp_tls_note_starttls_offer = yes'
postconf -e 'smtp_enforce_tls = yes'
#postconf -e "virtual_mailbox_domains = ${domain}"


echo "@${domain} smtp:[${sender}]" > /etc/postfix/transport
postmap /etc/postfix/transport
postconf -e "transport_maps                  =      hash:/etc/postfix/transport"




mkdir -p /etc/opendkim/keys

echo "localhost" > /etc/opendkim/TrustedHosts
echo "127.0.0.1" >> /etc/opendkim/TrustedHosts
echo "${sender}" >> /etc/opendkim/TrustedHosts

echo "mail._domainkey.${domain} ${domain}:mail:/etc/opendkim/keys/${domain}/mail.private" > /etc/opendkim/KeyTable
echo "*@${domain} mail._domainkey.${domain}" > /etc/opendkim/SigningTable

mkdir /etc/opendkim/keys/$domain
cd /etc/opendkim/keys/$domain
opendkim-genkey -s mail -d $domain

chown -R opendkim:opendkim /etc/opendkim

/etc/init.d/opendkim restart
/etc/init.d/postfix restart


mkdir /etc/nginx/sites-backuped/
cp /etc/nginx/sites-enabled/default /etc/nginx/sites-backuped/default.$$
echo "server {" > /etc/nginx/sites-enabled/default 
echo "listen 80;" >> /etc/nginx/sites-enabled/default 
echo "root /var/www/html/;" >> /etc/nginx/sites-enabled/default 
echo "index index.html index.htm index.nginx-debian.html index.php;" >> /etc/nginx/sites-enabled/default 
echo "server_name ${domain} www.${domain};" >> /etc/nginx/sites-enabled/default 
echo "location / {" >> /etc/nginx/sites-enabled/default 
echo "proxy_pass http://${default_sender_ip};" >> /etc/nginx/sites-enabled/default 
echo "  }" >> /etc/nginx/sites-enabled/default
echo "  }" >> /etc/nginx/sites-enabled/default

echo "server {" >> /etc/nginx/sites-enabled/default 
echo "listen 443 ssl;" >> /etc/nginx/sites-enabled/default 
echo "ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;" >> /etc/nginx/sites-enabled/default 
echo "ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;" >> /etc/nginx/sites-enabled/default 
echo "root /var/www/html/;" >> /etc/nginx/sites-enabled/default 
echo "index index.html index.htm index.nginx-debian.html index.php;" >> /etc/nginx/sites-enabled/default 
echo "server_name ${domain} www.${domain};" >> /etc/nginx/sites-enabled/default 
echo "location / {" >> /etc/nginx/sites-enabled/default
echo "proxy_pass http://${default_sender_ip};" >> /etc/nginx/sites-enabled/default 
echo "  }" >> /etc/nginx/sites-enabled/default
echo "  }" >> /etc/nginx/sites-enabled/default


echo "server {" >> /etc/nginx/sites-enabled/default 
echo "listen 80;" >> /etc/nginx/sites-enabled/default 
echo "root /var/www/html/;" >> /etc/nginx/sites-enabled/default 
echo "index index.html index.htm index.nginx-debian.html index.php;" >> /etc/nginx/sites-enabled/default 
echo "server_name mail.${domain};" >> /etc/nginx/sites-enabled/default 
echo "location / {" >> /etc/nginx/sites-enabled/default 
echo "try_files \$uri \$uri/ /index.html =404;" >> /etc/nginx/sites-enabled/default 
echo "  }" >> /etc/nginx/sites-enabled/default 

 echo "  location ~ \.php$ { " >> /etc/nginx/sites-enabled/default 
               echo "  try_files \$uri =404;" >> /etc/nginx/sites-enabled/default 
               echo "  include fastcgi_params;" >> /etc/nginx/sites-enabled/default 
               echo "  fastcgi_pass unix:/var/run/php5-fpm.sock;" >> /etc/nginx/sites-enabled/default 
               echo "  fastcgi_split_path_info ^(.+\.php)(.*)\$;" >> /etc/nginx/sites-enabled/default 
                echo " fastcgi_param  SCRIPT_FILENAME \$document_root\$fastcgi_script_name;" >> /etc/nginx/sites-enabled/default 
        echo " } " >> /etc/nginx/sites-enabled/default 

cat << "EOF" >> /etc/nginx/sites-enabled/default
location /cgi-bin/ {
        root  /var/www/html/;
        fastcgi_pass  unix:/var/run/fcgiwrap.socket;
        include /etc/nginx/fastcgi_params;
        fastcgi_param SCRIPT_FILENAME  $document_root$fastcgi_script_name;
EOF

echo "  }" >> /etc/nginx/sites-enabled/default

mkdir /var/www/html/cgi-bin/

echo '#!/bin/bash' > /var/www/html/cgi-bin/tail.cgi
echo 'echo Content-type: text/plain' >> /var/www/html/cgi-bin/tail.cgi
echo 'echo ""' >>/var/www/html/cgi-bin/tail.cgi
echo 'sudo tail -n 40 /var/log/mail.log' >> /var/www/html/cgi-bin/tail.cgi

echo '#!/bin/bash' > /var/www/html/cgi-bin/mailq.cgi
echo 'echo Content-type: text/plain' >> /var/www/html/cgi-bin/mailq.cgi
echo 'echo ""' >> /var/www/html/cgi-bin/mailq.cgi
echo 'mailq' >> /var/www/html/cgi-bin/mailq.cgi

echo '#!/bin/bash' > /var/www/html/cgi-bin/queue.cgi
echo 'echo Content-type: text/html' >> /var/www/html/cgi-bin/queue.cgi
echo 'echo ""' >> /var/www/html/cgi-bin/queue.cgi
echo $'INODES=`df -hi | sed -n \'2p\' |awk \'{print $5}\' | grep -v U|cut -d% -f1`' >> /var/www/html/cgi-bin/queue.cgi
echo 'LIMIT=50' >> /var/www/html/cgi-bin/queue.cgi
echo 'if [ "$INODES" -lt "$LIMIT" ]' >> /var/www/html/cgi-bin/queue.cgi
echo 'then' >> /var/www/html/cgi-bin/queue.cgi
echo 'echo "1"' >> /var/www/html/cgi-bin/queue.cgi
echo 'else' >> /var/www/html/cgi-bin/queue.cgi
echo 'echo "0"' >> /var/www/html/cgi-bin/queue.cgi
echo 'fi' >> /var/www/html/cgi-bin/queue.cgi

echo '#!/bin/bash' > /var/www/html/cgi-bin/qshape.cgi
echo 'echo Content-type: text/plain' >> /var/www/html/cgi-bin/qshape.cgi
echo 'echo ""' >> /var/www/html/cgi-bin/qshape.cgi
echo 'PATH=$PATH:/usr/sbin' >> /var/www/html/cgi-bin/qshape.cgi
echo 'sudo /usr/sbin/qshape active bounce corrupt defer deferred flush hold incoming' >> /var/www/html/cgi-bin/qshape.cgi
echo 'echo ""' >> /var/www/html/cgi-bin/qshape.cgi


/etc/init.d/nginx restart

chmod +x /var/www/html/cgi-bin/*
echo "========== NASTAVENI DNS =========" > /var/www/html/mail.txt
echo "                MX      ${domain}" >> /var/www/html/mail.txt
echo "_adsp._domainkey  TXT    dkim=all" >> /var/www/html/mail.txt
echo "                TXT     v=spf1 ip4:${IP_ADRESA} -all" >> /var/www/html/mail.txt
echo "		A       ${sender}" >> /var/www/html/mail.txt
echo "mail		A       ${IP_ADRESA}" >> /var/www/html/mail.txt

for i in $(seq 0 $SEQUENCE);
do 
DOCASNE="$((IPKA4 + i))"
echo "mail${i}  A       ${IPKA1}.${IPKA2}.${IPKA3}.${DOCASNE}" >> /var/www/html/mail.txt
done
echo "_dmarc		TXT	v=DMARC1; p=quarantine; sp=quarantine; adkim=r; aspf=r;" >> /var/www/html/mail.txt
for i in $(seq 0 $SEQUENCE); 
do 
DOCASNE="$((IPKA4 + i))"
echo "      TXT v=spf1 ip4:${IPKA1}.${IPKA2}.${IPKA3}.${DOCASNE} -all" >> /var/www/html/mail.txt
done

#resultDKIM=$(cat /etc/opendkim/keys/$domain/mail.txt | sed 's/\t  //g')
resultDKIM=$(sed -e 's/"//g' -e "s/.*(\(.*\) ).*/\1;/" <<< $(cat /etc/opendkim/keys/${domain}/mail.txt))

echo $resultDKIM  | sed 's/"//g' >> /var/www/html/mail.txt
echo "========= NASTAVENI PTR ==========" >> /var/www/html/mail.txt
echo "${IP_ADRESA} PTR ZAZNAM ${domain}" >> /var/www/html/mail.txt
for i in $(seq 0 $SEQUENCE); 
do 
DOCASNE="$((IPKA4 + i))"
echo "${IPKA1}.${IPKA2}.${IPKA3}.${DOCASNE} PTR ZAZNAM mail${i}.${domain}" >> /var/www/html/mail.txt
done
echo "==================================" >> /var/www/html/mail.txt

# send to wapi
if [ $wapi_enabled -eq 1 ]; then
    curl --data "domain=${domain}" --data "mail=${IP_ADRESA}" \
         --data "root=${IP_ADRESA}" --data "mx=${domain}" \
         --data "dkim=${resultDKIM}" \
         --data "pass=${wapi_pass}" \
         "${default_wapi_url}"
fi

echo "konfiguraci naleznete na http://${IP_ADRESA}/mail.txt" 

cat > /var/www/html/menu.php <<- "EOF"
<FRAMESET ROWS="100,*">
<FRAME NAME="top" SRC="menu_.php" scrolling="no" frameborder="0" >
<FRAME NAME="main" SRC="manage.php" scrolling="auto" frameborder="0" >
</FRAMESET>
EOF

rm -r /var/www/html/*.html

echo "" > /var/www/html/index.html



cat > /var/www/html/menu_.php <<- "EOF"
<base target="main">
<table width=100% border=0 cellspacing=0 valign="top">
<tr>
        <td align="left">
        <b><?=php_uname('n') ?></b>
        &nbsp;::&nbsp;
        <a href="./manage.php">manage</a>
        &nbsp;::&nbsp;
        <a href="./cgi-bin/mailq.cgi">mailq.cgi</a>
        &nbsp;::&nbsp;
        <a href="./cgi-bin/qshape.cgi">qshape.cgi</a>
        &nbsp;::&nbsp;
        <a href="./cgi-bin/queue.cgi">queue.cgi</a>
        &nbsp;::&nbsp;
        <a href="./cgi-bin/tail.cgi">tail.cgi</a>
        </td>
</tr>
</table>
EOF

cat > /var/www/html/manage.php <<- "EOF"
<?php
if($_POST['akce'] == "postfix-start"){
exec("sudo /etc/init.d/postfix start");
}
if($_POST['akce'] == "postfix-stop"){
exec("sudo /etc/init.d/postfix stop");
}
if($_POST['akce'] == "postfix-restart"){
exec("sudo /etc/init.d/postfix restart");
}
if($_POST['akce'] == "postfix-queue-stop"){
exec("sudo postsuper -h ALL");
}
if($_POST['akce'] == "postfix-queue-start"){
exec("sudo postsuper -H ALL");
}
if($_POST['akce'] == "postfix-queue-flush"){
exec("sudo postsuper -d ALL");
}
?>
<form method="post">
<button type="submit" name="akce" value="postfix-start">Zapnout postfix</button> <button type="submit" name="akce" value="postfix-stop">Vypnout postfix</button> <button type="submit" name="postfix-restart">Restart postfixu</button>
<br><br>
<button type="submit" name="akce" value="postfix-queue-start">Zapnout frontu</button> <button type="submit" name="akce" value="postfix-queue-stop">Pozastavit frontu</button> <button type="submit" name="akce" value="postfix-queue-flush">Smazat frontu</button>
</form>
EOF


