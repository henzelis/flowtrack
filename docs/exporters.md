# Exporter configuration

[← FlowSphera](../README.md) · [Install](install.md) · [Exporters](exporters.md) · [Features](features.md) · [Editions](editions.md) · [Backups](backups.md) · [Configuration](configuration.md) · [API](api.md) · [Security](security.md) · [Performance](performance.md)

**Which interfaces.** Enable export on every interface whose traffic you want to see: the WAN for
internet traffic, internal interfaces (LAN, VLANs, VPN tunnels) for traffic between your own networks.
Monitoring both directions (ingress and egress) is fine: when a flow is reported on the way in and again
on the way out, FlowSphera keeps one copy if the record carries the direction field (NetFlow v9
`DIRECTION` / IPFIX `flowDirection`), and Settings → Devices warns when an exporter sends copies that
cannot be told apart. The *Internet / Internal / All* selector in the top bar switches between internet
traffic and traffic between inside addresses. Inside traffic is shown client -> server: who started the session
(by the ports — the server is on a well-known port, otherwise on the lower one), the server and its service, what
the client sent (upload) and what the server answered (download); Top hosts adds how many inside hosts each one
connected to and how many connected to it.

**FortiGate (FortiOS 7.x)** — NetFlow v9, full rate:

```
config system netflow
    set active-flow-timeout 60
    config collectors
        edit 1
            set collector-ip <COLLECTOR_IP>
            set collector-port 2055
            set source-ip <FW_LAN_IP>
        next
    end
end
config system interface
    edit "wan"
        set netflow-sampler both
    next
    edit "internal"
        set netflow-sampler both
    next
end
```

`active-flow-timeout` defaults to 30 minutes; at 60 s long sessions show up in near real time. Interface
indexes: `show system interface <name> | grep snmp-index`. FortiOS exports per session, so a session that
crosses two sampled interfaces is still reported once. Wi-Fi SSID (VAP) interfaces cannot be sampled:
traffic between two SSIDs is not visible; traffic between an SSID and a sampled interface is.
FortiOS starts exporting sessions created after the sampler was enabled.

**Cisco IOS-XE** (Flexible NetFlow) — a record with `flow direction`, so egress copies can be removed:

```
flow record FT-REC
 match ipv4 source address
 match ipv4 destination address
 match ipv4 protocol
 match transport source-port
 match transport destination-port
 match interface input
 match flow direction
 collect interface output
 collect counter bytes long
 collect counter packets long
 collect timestamp sys-uptime first
 collect timestamp sys-uptime last
flow exporter FLOWTRACK
 destination <COLLECTOR_IP>
 transport udp 2055
 template data timeout 60
flow monitor FT-MON
 exporter FLOWTRACK
 record FT-REC
 cache timeout active 60
interface GigabitEthernet0/0/0
 ip flow monitor FT-MON input
 ip flow monitor FT-MON output
interface GigabitEthernet0/0/1
 ip flow monitor FT-MON input
 ip flow monitor FT-MON output
```

**MikroTik RouterOS 7**

```
/ip traffic-flow set enabled=yes interfaces=all active-flow-timeout=1m
/ip traffic-flow target add dst-address=<COLLECTOR_IP> port=2055 version=9
```

**Juniper**, **pmacct / Linux** and others: the *Connect device* dialog in the UI shows ready-made
snippets.

**SNMP (optional).** Tick *Read interface names and IP addresses over SNMP* in the device dialog, choose v2c
(community) or v3 (user, authentication MD5 / SHA / SHA-2, privacy DES / AES / AES-192 / AES-256): the dialog adds
the matching SNMP configuration to the device snippet, and *Test SNMP* checks it before saving. The device must let
the FlowSphera server poll it (UDP 161; FortiGate: `allowaccess snmp` on the interface, the community's host list).
FlowSphera polls read-only with the net-snmp tools (package `snmp`, installed by the installer); the community and
v3 passwords are kept in `/var/lib/flowtrack/snmp.json` (readable by the service only) and are never sent back to
the browser. Use the same `ifIndex` for SNMP and NetFlow — on Cisco IOS keep `snmp-server ifindex persist`.
