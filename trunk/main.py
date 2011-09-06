#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

# modules imports
import sys
import __builtin__
import inspect

import ConfigParser
from optparse import OptionParser

from common import *
from report import *
from metrics import *
from analyzor import *

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

    if len(IP4inbound) > 0:
        netManagement = IP4outbound.split(',')
        __builtin__.IPv4trustedNetManagementServers = list()
        for entry in netManagement:
            entry = entry.split('/')
            if len(entry) == 1:
                entry.append('32')
            entry.append(dotted2Netmask(entry[1]))
            entry.append(netmask2wildcard(entry[2]))
            entry.append(networkAddress(entry[0], entry[2]))
            __builtin__.IPv4trustedNetManagementServers.append(entry)
    else:
        __builtin__.IPv4trustedNetManagementServers = None

    if len(IP4inbound) > 0:
        netStations = IP4inbound.split(',')
        __builtin__.IPv4trustedNetManagementStations = list()
        for entry in netStations:
            entry = entry.split('/')
            if len(entry) == 1:
                entry.append('32')
            entry.append(dotted2Netmask(entry[1]))
            entry.append(netmask2wildcard(entry[2]))
            entry.append(networkAddress(entry[0], entry[2]))
            __builtin__.IPv4trustedNetManagementStations.append(entry)
    else:
        __builtin__.IPv4trustedNetManagementStations = None

except:
    print "Template arguments: parameters errors."
    print sys.exc_info()
    exit(1)

print writeHeader()

# configuration file reading
lines = readCfg(options.configurationFile)
__builtin__.wholeconfig = lines

# Cisco IOS configuration file type checking
checkCfg(lines)

__builtin__.genericCfg = addBasicInfo(lines)

# Add metrics for the Management Plane.  
MgmtPlane = metrics()
# Add metrics for the Control Plane.  
CtrlPlane = CPmetrics()
# Add metrics for the Data Plane.  
DataPlane = DPmetrics()
# Add metric for the interfaces.  
Interfaces = IFSmetrics()
# Add metric for the IPv4 ACLs.  
AclsV4 = ACLV4metrics()
# Add metric for the IPv6 ACLs.  
AclsV6 = ACLV6metrics()

# Find interfaces (ifaceCfg).  
ifaceCfg = populateInterfaces(lines,Interfaces)
for i in range(0, len(ifaceCfg)):
    ifaceCfg[i].populateMetricsFromConfig()

# Find IPv4 access-list (aclIPv4).  
aclIPv4 = populateACLv4(lines, AclsV4)
for i in range(0, len(aclIPv4)):
    aclIPv4[i].populateMetricsFromConfig()

# Find IPv6 access-list (aclIPv6).  
aclIPv6 = populateACLv6(lines, AclsV6)
for i in range(0, len(aclIPv6)):
    aclIPv6[i].populateMetricsFromConfig()

# Add generic metrics.  
CdpProtocol                         = MgmtPlane.addMetric('cdp')
LldpProtocol                        = MgmtPlane.addMetric('lldp')
__builtin__.console                 = MgmtPlane.addMetric('consolePort')
__builtin__.aux                     = MgmtPlane.addMetric('auxPort')
__builtin__.motd                    = MgmtPlane.addMetric('BannerMotd')
__builtin__.banLogin                = MgmtPlane.addMetric('BannerLogin')
__builtin__.banExec                 = MgmtPlane.addMetric('BannerExec')
__builtin__.genericServices         = MgmtPlane.addMetric('genericSvcs')
__builtin__.memoryCpu               = MgmtPlane.addMetric('memCpu')
__builtin__.exceptionCrashinfo      = MgmtPlane.addMetric('exceptions')
__builtin__.pwdManagement           = MgmtPlane.addMetric('pwdMgmt')
__builtin__.ManagementProtection    = MgmtPlane.addMetric('MgmtPP')
__builtin__.tacacsPlusRedundant     = MgmtPlane.addMetric('tacacsRedun')
__builtin__.tacacsPlusAuth          = MgmtPlane.addMetric('tacacsAuthe')
__builtin__.tacacsPlusAuthorization = MgmtPlane.addMetric('tacacsAutho')
__builtin__.tacacsPlusAccounting    = MgmtPlane.addMetric('tacacsAccou')
__builtin__.snmp                    = MgmtPlane.addMetric('snmp')
__builtin__.syslog                  = MgmtPlane.addMetric('syslog')
__builtin__.archive                 = MgmtPlane.addMetric('archive')
icmpUnreachable                     = CtrlPlane.addMetric('icmpunreach')
proxyArp                            = CtrlPlane.addMetric('proxyarp')
__builtin__.ntp                     = CtrlPlane.addMetric('ntp')
__builtin__.tcp                     = CtrlPlane.addMetric('tcp')

# Launch generic engines.  
analyzorCdp(CdpProtocol, lines, ifaceCfg)
analyzorLldp(LldpProtocol, lines, ifaceCfg)
analyzorSNMP(lines, snmp)
analyzorSyslog(lines, syslog)
analyzorArchive(lines, archive)
analyzorICMPUnreachable(icmpUnreachable, lines, ifaceCfg)
analyzorARPproxy(proxyArp, lines, ifaceCfg)
analyzorNtp(lines, ntp)
analyzorTcp(lines, tcp)
analyzorServices(lines, genericServices)
analyzorMemCpu(lines, memoryCpu)
analyzorCrashinfo(lines, exceptionCrashinfo)
analyzorPasswordManagement(lines, pwdManagement)
analyzorMPP(lines, vtyList, vtyCfg, ManagementProtection)

# motd banner
bannerMotd = parseBannerMOTD(lines)
analyzorBanner(bannerMotd, motd, 0)

# login banner
bannerLogin = parseBannerLOGIN(lines)
analyzorBanner(bannerLogin, banLogin, 1)

# exec banner
bannerExec = parseBannerEXEC(lines)
analyzorBanner(bannerExec, banExec, 2)

# console port
consoleCfg = parseConsole(lines)
analyzorConsole(consoleCfg, console, lines)

# aux port
auxCfg = parseAux(lines)
analyzorAux(auxCfg,aux)

# vty
vtyCfg = parseVty(lines)
__builtin__.vtyList = []
for i in range (0, len(vtyCfg)):
    __builtin__.vtyList.append(MgmtPlane.addMetric('vtyPort'))
    __builtin__.vtyList[i].sessionNumbers = vtyCfg[i][0].split(' ')[2:]
for i in range(0, len(vtyList)):
    analyzorVty(vtyCfg[i],vtyList[i])

# AAA redundancy
mode = 'RedundantAAA'
analyzorTacacs(lines, tacacsPlusRedundant, mode)

# AAA authentication
mode = 'Authentication'
analyzorTacacs(lines, tacacsPlusAuth, mode)

# AAA authorization
mode = 'Authorization'
analyzorTacacs(lines, tacacsPlusAuthorization, mode)

# AAA accounting
mode = 'Accounting'
analyzorTacacs(lines, tacacsPlusAccounting, mode)

# If device is a router or a multilayer switch.  
if __builtin__.deviceType  == 'router' or
    __builtin__.deviceType == 'both':
    
    __builtin__.bgp        = CtrlPlane.addMetric('bgp')
    __builtin__.eigrp      = CtrlPlane.addMetric('eigrp')
    __builtin__.rip        = CtrlPlane.addMetric('rip')
    __builtin__.ospf       = CtrlPlane.addMetric('ospf')
    __builtin__.glbp       = CtrlPlane.addMetric('glbp')
    __builtin__.hsrp       = CtrlPlane.addMetric('hsrp')
    __builtin__.vrrp       = CtrlPlane.addMetric('vrrp')
    icmpRedirects          = DataPlane.addMetric('icmpredirects')
    __builtin__.ipoptions  = DataPlane.addMetric('ipoptions')
    __builtin__.ipsrcroute = DataPlane.addMetric('ipsourceroute')
    __builtin__.denyicmp   = DataPlane.addMetric('denyIcmpAnyAny')
    __builtin__.ipfrags    = DataPlane.addMetric('IPfragments')
    __builtin__.urpf       = DataPlane.addMetric('urpf')
    __builtin__.netflow    = DataPlane.addMetric('netflow')
    __builtin__.tclsh = CtrlPlane.addMetric('tclsh')
    
    analyzorBgp(lines, bgp, aclIPv4)
    analyzorEigrp(lines, eigrp, ifaceCfg)
    analyzorRip(lines, rip, ifaceCfg)
    analyzorOspf(lines, ospf, ifaceCfg)
    analyzorGlbp(lines, glbp, ifaceCfg)
    analyzorHsrp(lines, hsrp, ifaceCfg)
    analyzorVrrp(lines, vrrp, ifaceCfg)
    analyzorICMPRedirects(icmpRedirects, lines, ifaceCfg)
    analyzorIPoptions(lines, ipoptions)
    analyzorIPsrcRoute(lines, ipsrcroute)
    analyzorICMPdeny(lines, denyicmp)
    analyzorIPfragments(lines, ipfrags)
    analyzorURPF(lines, urpf, ifaceCfg)
    analyzorNetflow(lines, netflow, ifaceCfg)
    analyzorTclSH(lines, tclsh)
    
    # multicast
    if __builtin__.genericCfg.multicast == "Enabled":
        __builtin__.multicast = CtrlPlane.addMetric('multicast')
        analyzorMulticast(lines, multicast)

    # qos
    if __builtin__.genericCfg.qos == "Enabled":
        __builtin__.qos = CtrlPlane.addMetric('qos')
        analyzorQos(lines, qos, ifaceCfg)

    # IPv6
    if __builtin__.genericCfg.ipv6 == "Enabled":
        __builtin__.urpfv6 = DataPlane.addMetric('urpfv6')
        analyzorURPFv6(lines, urpfv6, ifaceCfg)

    # IPsec
    if __builtin__.genericCfg.ipsec == "Enabled":
        __builtin__.ipsec = DataPlane.addMetric('ipsec')
        analyzorIPSEC(lines, ipsec)

# If device is a switch or a multilayer switch.  
if __builtin__.deviceType  == 'switch' or
    __builtin__.deviceType == 'both':
    
    __builtin__.portsecurity = DataPlane.addMetric('portsecurity')
    __builtin__.level2protocols = DataPlane.addMetric('level2protocols')

    analyzorPortSecurity(lines, portsecurity, ifaceCfg)
    analyzorLevel2Protocols(lines, level2protocols, ifaceCfg)

    # IPv6
    if __builtin__.genericCfg.ipv6 == "Enabled":
        __builtin__.ipv6 = DataPlane.addMetric('ipv6')
        analyzorIPv6(lines, ipv6, aclIPv6, ifaceCfg)

# reporting
output = {
    'stdout': lambda : stdoutReport(genericCfg,
                                    MgmtPlane.metricsList,
                                    CtrlPlane.metricsList,
                                    DataPlane.metricsList),
                                    
    'csv'   : lambda : csvReport   (__builtin__.outputFile,
                                    MgmtPlane.metricsList,
                                    CtrlPlane.metricsList,
                                    DataPlane.metricsList),
                                    
    'html'  : lambda : htmlReport  (__builtin__.outputFile, 
                                    genericCfg,
                                    MgmtPlane.metricsList,
                                    CtrlPlane.metricsList,
                                    DataPlane.metricsList),
                                    
    'pdf'   : lambda : pdfReport   (__builtin__.outputFile,
                                    genericCfg,
                                    MgmtPlane.metricsList,
                                    CtrlPlane.metricsList,
                                    DataPlane.metricsList)
    }[outputType]()

# End of program
print writeFooter()
