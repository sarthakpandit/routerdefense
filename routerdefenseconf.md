**Table of contents:**


There are two sections: _engine_ and _reporting_.

**Engine** tunes the accuracy of the routerdefense analysis.

**Reporting** declares the format and the destination filename.



# Engine section #

| _iosversion_ | The IOS version is used by some functions like the service password recovery's one to adjust the recommandations: upgrade the IOS release or do a configuration change. Global variable: builtin.iosVersion. Code excerpt: if **builtin.iosVersion >= 12.314:**. Variable used by the reporting functions: **genericCfg.iosVersion**. |
|:-------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| _platform_   | Router/Switch/Both.<br /> **if builtin.deviceType == 'router' or builtin.deviceType == 'both':** eigrp, bgp, rip, ospf, glbp, hsrp, vrrp, urpf, netflow, icmp redirects, ip options, ip source route, icmp any any, fragments <br /> **if builtin.deviceType == 'switch' or builtin.deviceType == 'both':** _portsecurity_ and _level 2 protocols_ specific functions. |

# Reporting section #

| _format_ | stdout/CSV/HTML/PDF output are supported. **HTML** is the most tested format. |
|:---------|:------------------------------------------------------------------------------|
| _filename_ | Output destination filename. Absolute pathname optional. Directory permissions rights are checked prior the report generation. |

# routerdefense.conf example #

```
[engine]
; Cisco IOS version. Used for more accurate recommandations. ( Optionnal )
iosversion = 12.2(50)SG

; Platform assessed. Possible values: router, switch, both
; Both is specific to multilayer switches and platforms like Cat4k or Cat6k
platform = both

; Authorized nodes to communicate with the device in the outbound direction: SNMP, SYSLOG
; Possibles values examples (comma-separated) : 192.168.100.0/24, 192.168.1.1
IP4outbound=

; Authorized nodes to do VTY inbound sessions (Telnet, SSH)
; Possibles values examples (comma-separated) : 192.168.100.0/24, 192.168.1.1
IP4inbound=

[reporting]
; format possible values: stdout, csv, html, pdf
format = html

; used only for the csv, html and pdf reports
filename=report-routerdefense.html
```