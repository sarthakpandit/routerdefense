# -*- coding: iso-8859-1 -*-

__docformat__ = 'restructuredtext'
__version__ = '$Id$'

# modules imports
import sys
import __builtin__
import inspect

import ConfigParser
from optparse import OptionParser

from common import *
from metrics import *
from engines import *
from reports import *

# arguments parsing
parser = OptionParser()
parser.add_option("-c", "--config",
                  dest = "configurationFile",
                  help = "Configuration file.")
parser.add_option("-t", "--template",
                  dest = "templateFile",
                  help = "Template file.")
(options, args) = parser.parse_args()

if ((len(sys.argv) <= 3) or
    (options.configurationFile is None) ):
    parser.error("Arguments: no configuration nor template file.")

# template parsing
try:
    config = ConfigParser.ConfigParser()
    config.read(options.templateFile)
    __builtin__.iosVersion = config.get('engine'   , 'iosversion')
    __builtin__.deviceType = config.get('engine'   , 'platform')
    IP4outbound            = config.get('engine'   , 'IP4outbound')
    IP4inbound             = config.get('engine'   , 'IP4inbound')
    __builtin__.outputType = config.get('reporting', 'format')
    __builtin__.outputFile = config.get('reporting', 'filename')
except ConfigParser.Error:
    print "Template arguments: parameters errors."
    print sys.exc_info()
    exit(1)

if len(IP4inbound) > 0:
    netManagement = IP4outbound.split(',')
    __builtin__.ipv4_mgmt_outbound = list()
    for entry in netManagement:
        entry = entry.split('/')
        if len(entry) == 1:
            entry.append('32')
        entry.append(dotted_netmask(entry[1]))
        entry.append(netmask_wildcard(entry[2]))
        entry.append(network_address(entry[0], entry[2]))
        __builtin__.ipv4_mgmt_outbound.append(entry)
else:
    __builtin__.ipv4_mgmt_outbound = None

if len(IP4inbound) > 0:
    netStations = IP4inbound.split(',')
    __builtin__.ipv4_mgmt_inbound = list()
    for entry in netStations:
        entry = entry.split('/')
        if len(entry) == 1:
            entry.append('32')
        entry.append(dotted_netmask(entry[1]))
        entry.append(netmask_wildcard(entry[2]))
        entry.append(network_address(entry[0], entry[2]))
        __builtin__.ipv4_mgmt_inbound.append(entry)
else:
    __builtin__.ipv4_mgmt_inbound = None

print stdout_header()

# configuration file reading
lines = read_cfg(options.configurationFile)
__builtin__.wholeconfig = lines

# Cisco IOS configuration file type checking
check_cfg(lines)

__builtin__.genericCfg = addBasicInfo(lines)

# Add metrics for the Management Plane.
MgmtPlane = metrics()
# Add metrics for the Control Plane.
CtrlPlane = CPmetrics()
# Add metrics for the Data Plane.
DataPlane = DPmetrics()
# Add metric for the interfaces.
interfaces = IFSmetrics()
# Add metric for the IPv4 ACLs.
AclsV4 = ACLV4metrics()
# Add metric for the IPv6 ACLs.
AclsV6 = ACLV6metrics()

# Find interfaces (ifaceCfg).
ifaceCfg = populate_ifaces(lines,interfaces)
for i in range(0, len(ifaceCfg)):
    ifaceCfg[i].get_metrics_from_config()

# Find IPv4 access-list (aclIPv4).
aclIPv4 = populate_acl_v4(lines, AclsV4)
for i in range(0, len(aclIPv4)):
    aclIPv4[i].get_metrics_from_config()

# Find IPv6 access-list (aclIPv6).
aclIPv6 = populate_acl_v6(lines, AclsV6)
for i in range(0, len(aclIPv6)):
    aclIPv6[i].get_metrics_from_config()

# Add generic metrics.
CdpProtocol                         = MgmtPlane.add('cdp')
LldpProtocol                        = MgmtPlane.add('lldp')
__builtin__.console                 = MgmtPlane.add('consolePort')
__builtin__.aux                     = MgmtPlane.add('auxPort')
__builtin__.motd                    = MgmtPlane.add('BannerMotd')
__builtin__.banLogin                = MgmtPlane.add('BannerLogin')
__builtin__.banExec                 = MgmtPlane.add('BannerExec')
__builtin__.genericServices         = MgmtPlane.add('genSvcs')
__builtin__.memoryCpu               = MgmtPlane.add('memCpu')
__builtin__.exceptionCrashinfo      = MgmtPlane.add('exceptions')
__builtin__.pwdManagement           = MgmtPlane.add('pwdMgmt')
__builtin__.ManagementProtection    = MgmtPlane.add('MgmtPP')
__builtin__.tacacsPlusRedundant     = MgmtPlane.add('tacacsRed')
__builtin__.tacacsPlusAuth          = MgmtPlane.add('tacacsThe')
__builtin__.tacacsPlusAuthorization = MgmtPlane.add('tacacsTho')
__builtin__.tacacsPlusAccounting    = MgmtPlane.add('tacacsAcc')
__builtin__.snmp                    = MgmtPlane.add('snmp')
__builtin__.syslog                  = MgmtPlane.add('syslog')
__builtin__.archive                 = MgmtPlane.add('archive')
icmpUnreachable                     = CtrlPlane.add('icmpunreach')
proxyArp                            = CtrlPlane.add('proxyarp')
__builtin__.ntp                     = CtrlPlane.add('ntp')
__builtin__.tcp                     = CtrlPlane.add('tcp')

# Launch generic engines.
engine_cdp(CdpProtocol, lines, ifaceCfg)
engine_lldp(LldpProtocol, lines, ifaceCfg)
engine_snmp(lines, snmp)
engine_syslog(lines, syslog)
engine_archive(lines, archive)
engine_icmp_unreach(icmpUnreachable, lines, ifaceCfg)
engine_arp_proxy(proxyArp, lines, ifaceCfg)
engine_ntp(lines, ntp)
engine_tcp(lines, tcp)
engine_services(lines, genericServices)
engine_mem_cpu(lines, memoryCpu)
engine_crashinfo(lines, exceptionCrashinfo)
engine_password_management(lines, pwdManagement)

# motd banner
bannerMotd = parse_motd(lines)
engine_banner(bannerMotd, motd, 0)

# login banner
bannerLogin = parse_login_banner(lines)
engine_banner(bannerLogin, banLogin, 1)

# exec banner
bannerExec = parse_exec_banner(lines)
engine_banner(bannerExec, banExec, 2)

# console port
consoleCfg = parse_console(lines)
engine_console(consoleCfg, console, lines)

# aux port
auxCfg = parse_aux(lines)
engine_aux(auxCfg,aux)

# vty
vtyCfg = parse_vty(lines)
__builtin__.vtyList = []
for i in range (0, len(vtyCfg)):
    __builtin__.vtyList.append(MgmtPlane.add('vtyPort'))
    __builtin__.vtyList[i].sessionNumbers = vtyCfg[i][0].split(' ')[2:]
for i in range(0, len(vtyList)):
    engine_vty(vtyCfg[i],vtyList[i])

engine_mpp(lines, vtyList, vtyCfg, ManagementProtection)

# AAA redundancy
mode = 'RedundantAAA'
engine_tacacs(lines, tacacsPlusRedundant, mode)

# AAA authentication
mode = 'Authentication'
engine_tacacs(lines, tacacsPlusAuth, mode)

# AAA authorization
mode = 'Authorization'
engine_tacacs(lines, tacacsPlusAuthorization, mode)

# AAA accounting
mode = 'Accounting'
engine_tacacs(lines, tacacsPlusAccounting, mode)

# If device is a router or a multilayer switch.
if (__builtin__.deviceType  == 'router' or
    __builtin__.deviceType == 'both'):

    __builtin__.bgp        = CtrlPlane.add('bgp')
    __builtin__.eigrp      = CtrlPlane.add('eigrp')
    __builtin__.rip        = CtrlPlane.add('rip')
    __builtin__.ospf       = CtrlPlane.add('ospf')
    __builtin__.glbp       = CtrlPlane.add('glbp')
    __builtin__.hsrp       = CtrlPlane.add('hsrp')
    __builtin__.vrrp       = CtrlPlane.add('vrrp')
    icmpRedirects          = DataPlane.add('icmpredirects')
    __builtin__.ipoptions  = DataPlane.add('ipoptions')
    __builtin__.ipsrcroute = DataPlane.add('ipsourceroute')
    __builtin__.denyicmp   = DataPlane.add('denyIcmpAnyAny')
    __builtin__.ipfrags    = DataPlane.add('IPfragments')
    __builtin__.urpf       = DataPlane.add('urpf')
    __builtin__.netflow    = DataPlane.add('netflow')
    __builtin__.tclsh = CtrlPlane.add('tclsh')

    engine_bgp(lines, bgp, aclIPv4)
    engine_eigrp(lines, eigrp, ifaceCfg)
    engine_rip(lines, rip, ifaceCfg)
    engine_ospf(lines, ospf, ifaceCfg)
    engine_glbp(lines, glbp, ifaceCfg)
    engine_hsrp(lines, hsrp, ifaceCfg)
    engine_vrrp(lines, vrrp, ifaceCfg)
    engine_icmp_redirects(icmpRedirects, lines, ifaceCfg)
    engine_ip_options(lines, ipoptions)
    engine_ip_src_route(lines, ipsrcroute)
    engine_icmp_deny(lines, denyicmp)
    engine_ipfrags(lines, ipfrags)
    engine_urpf(lines, urpf, ifaceCfg)
    engine_netflow(lines, netflow, ifaceCfg)
    engine_tclsh(lines, tclsh)

    # multicast
    if __builtin__.genericCfg.multicast == "Enabled":
        __builtin__.multicast = CtrlPlane.add('multicast')
        engine_multicast(lines, multicast)

    # qos
    if __builtin__.genericCfg.qos == "Enabled":
        __builtin__.qos = CtrlPlane.add('qos')
        engine_qos(lines, qos, ifaceCfg)

    # IPv6
    if __builtin__.genericCfg.ipv6 == "Enabled":
        __builtin__.urpfv6 = DataPlane.add('urpfv6')
        engine_urpfv6(lines, urpfv6, ifaceCfg)

    # IPsec
    if __builtin__.genericCfg.ipsec == "Enabled":
        __builtin__.ipsec = DataPlane.add('ipsec')
        engine_ipsec(lines, ipsec)

# If device is a switch or a multilayer switch.
if (__builtin__.deviceType  == 'switch' or
    __builtin__.deviceType == 'both'):

    __builtin__.portsecurity = DataPlane.add('portsecurity')
    __builtin__.l2protos = DataPlane.add('l2protos')

    engine_port_security(lines, portsecurity, ifaceCfg)
    engine_layer2(lines, l2protos, ifaceCfg)

    # IPv6
    if __builtin__.genericCfg.ipv6 == "Enabled":
        __builtin__.ipv6 = DataPlane.add('ipv6')
        engine_ipv6(lines, ipv6, aclIPv6, ifaceCfg)

# reporting
output = {
    'stdout': lambda : stdout_report(genericCfg,
                                    MgmtPlane.metrics_list,
                                    CtrlPlane.metrics_list,
                                    DataPlane.metrics_list),

    'csv'   : lambda : csvReport   (__builtin__.outputFile,
                                    MgmtPlane.metrics_list,
                                    CtrlPlane.metrics_list,
                                    DataPlane.metrics_list),

    'html'  : lambda : htmlReport  (__builtin__.outputFile,
                                    genericCfg,
                                    MgmtPlane.metrics_list,
                                    CtrlPlane.metrics_list,
                                    DataPlane.metrics_list),

    'pdf'   : lambda : pdfReport   (__builtin__.outputFile,
                                    genericCfg,
                                    MgmtPlane.metrics_list,
                                    CtrlPlane.metrics_list,
                                    DataPlane.metrics_list)
    }[outputType]()

# End of program
print stdout_footer()
