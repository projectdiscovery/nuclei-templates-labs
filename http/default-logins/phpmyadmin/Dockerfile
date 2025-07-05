FROM debian:12

ENV MYSQL_ROOT_PASSWORD=root

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server apache2 php php-mysql php-json php-mbstring php-xml wget

RUN sed -i 's/^bind-address/#bind-address/' /etc/mysql/mariadb.conf.d/50-server.cnf && \
    echo "bind-address = 0.0.0.0" >> /etc/mysql/mariadb.conf.d/50-server.cnf

CMD ["mysqld_safe"]


RUN wget https://files.phpmyadmin.net/phpMyAdmin/5.1.1/phpMyAdmin-5.1.1-all-languages.tar.gz && \
    tar xzf phpMyAdmin-5.1.1-all-languages.tar.gz && \
    mv phpMyAdmin-5.1.1-all-languages/* /var/www/html/ && \
    rm -rf phpMyAdmin-5.1.1-all-languages phpMyAdmin-5.1.1-all-languages.tar.gz && \
    rm -f /var/www/html/index.html

RUN cp /var/www/html/config.sample.inc.php /var/www/html/config.php && \
    sed -i "s/localhost/127.0.0.1/g" /var/www/html/config.php && \
    sed -i "s/\/\/ \$cfg\['Servers'\]\[\$i\]\['AllowNoPassword'\]/\$cfg\['Servers'\]\[\$i\]\['AllowNoPassword'\]/g" /var/www/html/config.php

RUN service mariadb start && \
    mysql -u root -proot -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'root'; GRANT ALL ON *.* TO 'root'@'%' IDENTIFIED BY 'root' WITH GRANT OPTION; FLUSH PRIVILEGES;"

CMD service mariadb start && /usr/sbin/apache2ctl -D FOREGROUND

EXPOSE 80
EXPOSE 3306