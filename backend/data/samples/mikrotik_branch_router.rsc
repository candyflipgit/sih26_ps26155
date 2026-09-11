# RouterOS export
# model = RB4011iGS+
# serial-number: HGT8A1B2C3D4
# software id = 9K7X-QM2P
#
/system identity set name=BRANCH-RTR-07
/ip ssh set strong-crypto=yes
/ip ssh set allow-none-crypto=no
/ip ssh set host-key-size=4096
/ip service set telnet disabled=no port=23
/ip service set ftp disabled=yes
/ip service set www disabled=no port=80
/ip service set ssh disabled=no port=22
/ip service set www-ssl disabled=yes
/ip service set api disabled=yes
/ip service set winbox address=10.99.0.0/24
/system clock set time-zone-name=Asia/Kolkata
/system ntp client set enabled=yes primary-ntp=10.50.4.10
/system logging action set 1 remote=10.50.4.20 target=remote
/system logging add action=remote topics=critical
/system logging add action=remote topics=system,info
/snmp set enabled=yes contact=noc@corp.example.net location=Branch07
/snmp community set 0 name=public addresses=10.50.4.0/24 read-access=yes
/user set 0 name=admin group=full
/user add name=netops group=full password=Str0ngP@ssPhrase2026
/ip firewall filter add chain=input action=accept protocol=tcp dst-port=22
/ip firewall filter add chain=input action=drop connection-state=invalid
/interface bridge add name=bridge-lan
/ip address add address=10.99.0.14/24 interface=bridge-lan
