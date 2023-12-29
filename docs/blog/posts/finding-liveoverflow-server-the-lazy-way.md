---
description: TODO
authors:
    - techbrunch
date: 2022-12-12
---

Some quick notes on how to find LiveOverflow Minecraft server.

Proxy: 157.90.56.39 -> Minecraft Server: Version: N00bBot-rust-proxy (Protocol 760) Description: A Minecraft Server §4LO §bN§b0§b0§bb§bB§bo§bt §cProxy Online Players: 49 Maximum Players: 50
New proxy ip: 65.109.165.130

Real server: https://minecraft-statistic.net/en/server/65.109.68.176_25565/userbar/
https://www.shodan.io/host/65.109.68.176/raw



# Using Shodan

Shodan is the 

https://www.shodan.io/search/report?query=Minecraft

Usefull filters:

- asn:AS24940
- product:Minecraft
- port:25565
- org:"Hetzner Online GmbH"
- version:"Paper 1.19.2"
- shodan.module:"minecraft"

Shodan does not let filter on the description but it is indexed so we can add "LiveOverflow".

filters: https://www.shodan.io/search/filters

using uncover:

```
echo 'asn:AS24940 product:Minecraft port:25565 org:"Hetzner Online GmbH" LiveOverflow'|uncover -e shodan -silent
```

-> https://www.shodan.io/host/162.55.101.24 -> Wrong server

As far as I know there is now way to search in the Shodan history.

History -> https://www.shodan.io/host/155.248.209.22/history#25565

# ByPassing Script Kiddies protections

-> DEMO -> Check Protocol -> https://wiki.vg/Protocol#Game_Event

-> /net/minecraft/network/packet/s2c/play/GameStateChangeS2CPacket.class -> DEMO_MESSAGE_SHOWN

-> https://github.com/search?q=DEMO_MESSAGE_SHOWN&type=code

- https://github.com/IMXNOOBX/FuFuClient
- https://github.com/Cynosphere/parachute
- https://github.com/cally72jhb/vector-addon -> Meteor Addon !
- https://github.com/TangyKiwi/KiwiClient
- https://github.com/lemonnnnnnnnnnnnnn/SourHack-1.19.2

Made a small change to handle GameStateChangeS2CPacket.GAME_MODE_CHANGED