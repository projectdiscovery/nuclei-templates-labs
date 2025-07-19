FROM debian:12

ENV MYSQL_ROOT_PASSWORD=root

RUN apt-get update && apt install -y lsb-release apt-transport-https ca-certificates curl gnupg2
RUN curl -fsSL https://packages.sury.org/php/apt.gpg | gpg --dearmor -o /usr/share/keyrings/php-archive-keyring.gpg
RUN echo "deb [signed-by=/usr/share/keyrings/php-archive-keyring.gpg] https://packages.sury.org/php/ $(lsb_release -sc) main" | tee /etc/apt/sources.list.d/php.list
RUN apt update && apt install -y php7.1 php7.1-mysql php7.1-json php7.1-mbstring php7.1-xml mariadb-server apache2 wget

RUN sed -i 's/^bind-address/#bind-address/' /etc/mysql/mariadb.conf.d/50-server.cnf && \
    echo "bind-address = 0.0.0.0" >> /etc/mysql/mariadb.conf.d/50-server.cnf

CMD ["mysqld_safe"]


RUN wget https://files.phpmyadmin.net/phpMyAdmin/5.0.1/phpMyAdmin-5.0.1-all-languages.tar.gz && \
    tar xzf phpMyAdmin-5.0.1-all-languages.tar.gz && \
    mkdir -p /var/www/html/phpMyAdmin && \
    mv phpMyAdmin-5.0.1-all-languages/* /var/www/html/phpMyAdmin/ && \
    rm -rf phpMyAdmin-5.0.1-all-languages phpMyAdmin-5.0.1-all-languages.tar.gz

RUN cp /var/www/html/phpMyAdmin/config.sample.inc.php /var/www/html/phpMyAdmin/config.inc.php && \
    sed -i "s/localhost/0.0.0.0/g" /var/www/html/phpMyAdmin/config.inc.php && \
    sed -i "s/\/\/ \$cfg\['Servers'\]\[\$i\]\['AllowNoPassword'\]/\$cfg\['Servers'\]\[\$i\]\['AllowNoPassword'\] = true;/g" /var/www/html/phpMyAdmin/config.inc.php && \
    echo "\$cfg['Servers'][\$i]['auth_type'] = 'config';" >> /var/www/html/phpMyAdmin/config.inc.php && \
    echo "\$cfg['Servers'][\$i]['user'] = 'root';" >> /var/www/html/phpMyAdmin/config.inc.php && \
    echo "\$cfg['Servers'][\$i]['password'] = 'root';" >> /var/www/html/phpMyAdmin/config.inc.php


RUN service mariadb start && \
    mysql -u root -proot -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'root'; GRANT ALL ON *.* TO 'root'@'%' IDENTIFIED BY 'root' WITH GRANT OPTION; FLUSH PRIVILEGES;"

CMD service mariadb start && /usr/sbin/apache2ctl -D FOREGROUND

EXPOSE 80
EXPOSE 3306