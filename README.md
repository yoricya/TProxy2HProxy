__Программа прежде всего предназначена для мартрутизаторов на Linux__


_Переадресация соединений из LAN на TProxy:_
```
sudo ip rule add fwmark 463 lookup 100
sudo ip route add local 0.0.0.0/0 dev lo table 100

# HTTP
sudo iptables -t mangle -A PREROUTING -p tcp --dport 80 ! -s 127.0.0.1 -j TPROXY --on-port <T_PROXY_PORT> --tproxy-mark 463/0xFFFFFFFF

# TLS
sudo iptables -t mangle -A PREROUTING -p tcp --dport 443 ! -s 127.0.0.1 -j TPROXY --on-port <T_PROXY_PORT> --tproxy-mark 463/0xFFFFFFFF

# ! -s 127.0.0.1 --- Чтобы трафик уходил дальше в WAN а не зацикливался - исчключаем захват локального трафика.
```

___Примечание:___

Вместо `! -s 127.0.0.1` вероятно лучше использовать:
```
    -m iprange ! --src-range 127.0.0.1-127.0.0.1 \ # Локальный хост (localhost)
    -m iprange ! --src-range 192.168.0.150-192.168.0.150 \ # WAN-адрес шлюза (интерфейс, подключенный к роутеру провайдера)
    -m iprange ! --src-range 192.168.1.1-192.168.1.1 \ # LAN-адрес шлюза (интерфейс, обслуживающий внутреннюю сеть)
```

__TODO:__
- [ ] - Разобратся с ECH (Вероятно лучшим вариантом будет разрывать сокет кидая TLS alert, заметил что большинство клиентов в таком случае пытаются переподключится через TLS1.2)
- [ ] - Проверить прямое подключение
- [ ] - Тесты стабильности
- [ ] - Добавить/Проверить поддержку ipv6
- [ ] - Добавить SOCKS5 Proxy
