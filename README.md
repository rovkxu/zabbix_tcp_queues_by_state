# Zabbix Template to get values for TCP stack
https://danielfm.me/posts/painless-nginx-ingress.html

Support zabbix v3.4

    1) Import template to zabbix server

    2) Copy files to /etc/zabbix/scripts

Script usage:
    python check_tcp_stack.py -h


To DO:
    Still lack of support for UDP statistics
