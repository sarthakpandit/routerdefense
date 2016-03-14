/!\ Project moved to github : https://github.com/pello/routerdefense /!\


Router Defense deep dives into Cisco routers and switches configuration and do security recommandations. It gives the opportunity to audit network devices in a quick, efficient way and actionable practices. The author created this tool because he was frustrated of never seeing a network device with simple security best practices applied in the wild.

The tool has been released at the BRUCON 2010 conference.
Last update: February 2013

Include 140 tests.


[Documentation home](http://code.google.com/p/routerdefense/wiki/DocHome)



```
______            _             ______      __
| ___ \          | |            |  _  \    / _|
| |_/ /___  _   _| |_ ___ _ __  | | | |___| |_ ___ _ __  ___  ___
|    // _ \| | | | __/ _ \ '__| | | | / _ \  _/ _ \ '_ \/ __|/ _ |
|  \ \ (_) | |_| | ||  __/ |    | |/ /  __/ ||  __/ | | \__ \  __/
\_| \_\___/ \__,_|\__\___|_|    |___/ \___|_| \___|_| |_|___/\___|

=[ Cisco IOS security assessment tool
=[ http://code.google.com/p/routerdefense
=[ version 2012.1


=[ Generic information

    => Hostname: ROUTERLAB
    => IOS version: 12.2
    => Switching: Unknown
    => Multicast: Disabled
    => QoS: Disabled
    => IPv6: Disabled
    => IPSEC VPN: Disabled

[......]

=[ summary ]=

Management Plane

CDP: 1/1
LLDP: 1/1
Console port: 2/2
Aux port: 4/4
Vty lines: 3/5
MOTD banner: 1/2
LOGIN banner: 0/2
EXEC banner: 1/2
IOS TCP/UDP services: 12/15
CPU/Memory: 9/9
Exceptions/crashes: 1/1
Passwords and authentication management: 0/4
Management protection: 6/7
Tacacs+ servers redundancy: 1/1
Tacacs+ authentication: 1/3
Tacacs+ authorization: 4/5
Tacacs+ accounting: 4/5
SNMP: 3/9
Syslog: 7/9
Configuration Replace/Rollback: 3/5

Control Plane

ICMPv4 unreachable: 1/1
ARP proxy: 1/1
NTP: 1/1
TCP: 1/1
BGP: 0/6
EIGRP: 0/4
RIP: 0/1
OSPF: 4/5
GLBP: 0/1
HSRP: 0/1
VRRP: 0/1
TCLSH shell scripting: 1/1

Data Plane

ICMPv4 redirects: 1/1
IPv4 Options: 1/1
IPv4 source route: 1/1
ICMP deny any any: 1/1
IPv4 fragments: 1/1
Unicast Reverse Path Forwarding (IPv4): 1/1
Netflow: 1/1
Port Security: 3/5
Level 2: 4/9

```