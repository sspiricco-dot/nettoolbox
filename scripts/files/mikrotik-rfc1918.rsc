/ip firewall address-list
add list={{LIST_NAME}} address=10.0.0.0/8
add list={{LIST_NAME}} address=172.16.0.0/12
add list={{LIST_NAME}} address=192.168.0.0/16

/ip firewall filter
add chain=input in-interface-list={{WAN_LIST}} src-address-list={{LIST_NAME}} action=drop comment="Drop RFC1918 from WAN"
add chain=forward in-interface-list={{WAN_LIST}} src-address-list={{LIST_NAME}} action=drop comment="Drop RFC1918 forwarding from WAN"
