# Table of contents: #



# Introduction #

Routerdefense validates the security configuration of IOS devices.

The user must provides a "show run" to the tool.

Reporting supported formats are stdout, html5, csv and pdf.

[Python version and modules requirements](pythonRequirements.md)

# Run the tool #

The simplest method is to use the run\_routerdefense script.

```
$ more run_routerdefense
#! /bin/sh
DIR=$(dirname $0)
PYTHONPATH=$DIR exec python -B -m routerdefense.__init__ -c show_run.txt -t routerdefense.conf
```

_show\_run.txt_ is the Cisco IOS device configuration file.<br />
[routerdefense.conf](routerdefenseconf.md) is a configuration file to tune the routerdefense tool.

$ **./run\_routerdefense -c show\_run.txt -t routerdefense.conf**

# Specific security checks #

The other method is to use the only`*`.py scripts with the Cisco IOS device configuration file as argument.

$ **python -B onlyCONSOLE.sh show\_run.txt**

| **Script name** | **Description** |
|:----------------|:----------------|
| _onlyAUX.py_    | Check AUX lines security |
| _onlyCDP.py_    | Check CDP security |
| _onlyCONSOLE.py_ | Check CON lines security |
| _onlyLLDP.py_   | Check LLDP security |
| _onlyMSDP.py_   | Check Multicast Source Discovery Protocol (MSDP) security |
| _onlyURPF.py_   | Check Unicast Reverse Path Forwarding (URPF) security |

# Supported Tests #

| **Description** | **Family** |
|:----------------|:-----------|
| CDP             | Global services |
| LLDP            | Global services |
| Password recovery | Global services |
| TCP small servers | Global services |
| UDP small servers | Global services |
| Finger          | Global services |
| Bootp           | Global services |
| TCP keepalives (in) | Global services |
| TCP keepalives (out) | Global services |
| IP dhcp boot ignore | Global services |
| DHCP server     | Global services |
| MOP             | Global services |
| Domain lookup   | Global services |
| PAD             | Global services |
| HTTP            | Global services |
| HTTPS           | Global services |
| Service config  | Global services |
| Console session timeout | Console    |
| Console privilege zero | Console    |
| Aux session timeout | Aux        |
| Aux transport input | Aux        |
| Aux transport output | Aux        |
| Aux shell       | Aux        |
| Vty exec timeout | Vty        |
| Vty transport input | Vty        |
| Vty transport output | Vty        |
| IPv4 Vty access class | Vty        |
| IPv6 Vty access class | Vty        |
| Low Free CPU Threshold | Memory/CPU |
| Low Free IO Threshold | Memory/CPU |
| Memory reservation for critical notifications | Memory/CPU |
| Reserve Memory for Console Access | Memory/CPU |
| Detection and Correction of Redzone Corruption (IO) | Memory/CPU |
| Detection and Correction of Redzone Corruption (Processor) | Memory/CPU |
| CPU Thresholding Notification via SNMP | Memory/CPU |
| Scheduler process allocate | Memory/CPU |
| Scheduler processinterval | Memory/CPU |
| Automatic Deletion of Crashinfo Files | Crash      |
| Enable secret   | Access management |
| Service password encryption | Access management |
| Secret username and password | Access management |
| Anti-bruteforce | Access management |
| Secure HTTPS and SSH services | Management plane |
| SSH timeout     | Management plane |
| SSH authentication retries | Management plane |
| SSH source-interface | Management plane |
| SSH secure copy | Management plane |
| HTTP secure server | Management plane |
| Login bruteforce attempts | Management plane |
| Please define a MOTD | Banners    |
| The device hostname should not be included in the MOTD banner | Banners    |
| The device hostname should not be included in the LOGIN banner | Banners    |
| The device hostname should not be included in the EXEC banner | Banners    |
| Running AAA in the infrastructure | AAA        |
| TACACS rulez and RADIUS sucks | AAA        |
| Authentication fallback | AAA        |
| AAA authorization | AAA        |
| Level 0 commands authorization | AAA        |
| Level 1 commands authorization | AAA        |
| Level 15 commands authorization | AAA        |
| AAA accounting  | AAA        |
| Level 0 commands accounting | AAA        |
| Level 1 commands accounting | AAA        |
| Level 15 commands accounting | AAA        |
| TACACS Servers redundancy | AAA        |
| Too basic read-only community name | SNMP       |
| ACL required for the read-only community | SNMP       |
| Too basic read-write community name | SNMP       |
| ACL required for the read-write community | SNMP       |
| View Too basic read-only community name | SNMP       |
| View ACL required for the read-only communit | SNMP       |
| Too basic read-write community name | SNMP       |
| ACL required for the read-write community | SNMP       |
| Authentication and/or crypto on SNMP packets | SNMP       |
| Export logs to a remote server | Syslog     |
| Export trap messages to a remote server | Syslog     |
| Export buffer logs to a remote server | Syslog     |
| Never display logs on the console | Syslog     |
| Never display logs on vty sessions | Syslog     |
| Enlarge the size of logs buffer | Syslog     |
| Specify sending source interface | Syslog     |
| Timestamp configuration | Syslog     |
| Check syslog server availability via ARP resolution | Syslog     |
| Keep the configurations history | Archiving  |
| Only one admin change at a time | Archiving  |
| Prevent IOS deletion by hiding it in the Flash | Archiving  |
| Prevent configuration deletion | Archiving  |
| Archive configuration changes | Archiving  |
| Prevent CPU spikes | Control plane |
| No reply to packets that are intended for another device | Control plane |
| MD5 authentication | Control plane (NTP) |
| TTL hops number | Control plane (BGP) |
| AS Path Length limit | Control plane (BGP) |
| Peer MD5 authentication | Control plane (BGP) |
| Maximum prefixes threshold | Control plane (BGP) |
| Prefixes list IN/OUT | Control plane (BGP) |
| BGP infrastructure ACL | Control plane (BGP) |
| AS-PATH list IN/OUT | Control plane (BGP) |
| Passive interface default | Control plane (EIGRP) |
| MD5 authentication | Control plane (EIGRP) |
| Route filtering inbound | Control plane (EIGRP) |
| Route filtering outbound | Control plane (EIGRP) |
| MD5 authentication | Control plane (RIP) |
| Passive interface default | Control plane (OSPF) |
| MD5 authentication | Control plane (OSPF) |
| Route filtering in | Control plane (OSPF) |
| Route filtering out | Control plane (OSPF) |
| Maximum amount of LSAs | Control plane (OSPF) |
| MD5 authentication | Control plane (GLBP) |
| MD5 authentication | Control plane (HSRP) |
| MD5 authentication | Control plane (VRRP) |
| TCL shell abuse | Control plane (TCL) |
| SYN wait time   | Control plane (TCP) |
| MSDP SA Filter  | Control plane (Multicast) |
| Drop behavior   | Data plane (IPv4) |
| Source routing  | Data plane (IPv4) |
| Redirect packets | Data plane (IPv4) |
| Deny any any    | Data plane (IPv4) |
| Anti-IDS evasion | Data plane (IPv4) |
| IPv4 anti-spoofing | Data plane (IPv4) |
| IPv6 anti-spoofing | Data plane (IPv6) |
| Source routing prevention | Data plane (IPv6) |
| Port violation  | Data plane (Switching) |
| MAC address sticky | Data plane (Switching) |
| Total maximum MAC addresses | Data plane (Switching) |
| Access vlan maximum MAC addresses | Data plane (Switching) |
| Voice vlan maximum MAC addresses | Data plane (Switching) |
| DTP negotiation | Data plane (Switching) |
| Flow Control 802.3x | Data plane (Switching) |
| UDLD            | Data plane (Switching) |
| Default Vlan 1  | Data plane (Switching) |
| Unused ports    | Data plane (Switching) |
| VTP password definition | Data plane (Switching) |
| Spanning-tree BPDU guard | Data plane (Switching) |
| Spanning-tree Root guard | Data plane (Switching) |
| 802.1x          | Data plane (Switching) |
| IPSEC IKE SA call admission control | Data plane (IPSEC) |
| IPSEC IKE system resources usage | Data plane (IPSEC) |
| Exporting network flows for security monitoring | Data plane (Monitoring) |

# CVSS scoring #

[Associated CVSS scores to each Routerdefense test](cvssScores.md)

# Routerdefense code internals #

See doc/ directory.