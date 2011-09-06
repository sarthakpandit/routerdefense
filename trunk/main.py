#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-

from optparse import OptionParser
import sys
import __builtin__
import inspect
import ConfigParser
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
    (options.configurationFile == None) ):
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

# add metrics for the Management Plane
MgmtPlane = metrics()
# add metrics for the Management Plane
CtrlPlane = CPmetrics()
# add metrics for the Management Plane
DataPlane = DPmetrics()
# add metric for the interfaces
Interfaces = IFSmetrics()
# add metric for the IPv4 ACLs
AclsV4 = ACLV4metrics()
# add metric for the IPv6 ACLs
AclsV6 = ACLV6metrics()

ifaceCfg = populateInterfaces(lines,Interfaces)
for i in range(0, len(ifaceCfg)):
    ifaceCfg[i].populateMetricsFromConfig()

aclIPv4 = populateACLv4(lines, AclsV4)
for i in range(0, len(aclIPv4)):
    aclIPv4[i].populateMetricsFromConfig()

aclIPv6 = populateACLv6(lines, AclsV6)
for i in range(0, len(aclIPv6)):
    aclIPv6[i].populateMetricsFromConfig()

CdpProtocol = MgmtPlane.addMetric('cdp')
analyzorCdp(CdpProtocol, lines, ifaceCfg)

LldpProtocol = MgmtPlane.addMetric('lldp')
analyzorLldp(LldpProtocol, lines, ifaceCfg)

consoleCfg = parseConsole(lines)
__builtin__.console = MgmtPlane.addMetric('consolePort')
analyzorConsole(consoleCfg, console, lines)

auxCfg = parseAux(lines)
__builtin__.aux = MgmtPlane.addMetric('auxPort')
analyzorAux(auxCfg,aux)

vtyCfg = parseVty(lines)
__builtin__.vtyList = []
for i in range (0, len(vtyCfg)):
    __builtin__.vtyList.append(MgmtPlane.addMetric('vtyPort'))
    __builtin__.vtyList[i].sessionNumbers = vtyCfg[i][0].split(' ')[2:]
for i in range(0, len(vtyList)):
    analyzorVty(vtyCfg[i],vtyList[i])

bannerMotd = parseBannerMOTD(lines)
__builtin__.motd = MgmtPlane.addMetric('BannerMotd')
analyzorBanner(bannerMotd, motd, 0)

bannerLogin = parseBannerLOGIN(lines)
__builtin__.banLogin = MgmtPlane.addMetric('BannerLogin')
analyzorBanner(bannerLogin, banLogin, 1)

bannerExec = parseBannerEXEC(lines)
__builtin__.banExec = MgmtPlane.addMetric('BannerExec')
analyzorBanner(bannerExec, banExec, 2)

__builtin__.genericServices = MgmtPlane.addMetric('genericServices')
analyzorServices(lines, genericServices)

__builtin__.memoryCpu = MgmtPlane.addMetric('memCpu')
analyzorMemCpu(lines, memoryCpu)

__builtin__.exceptionCrashinfo = MgmtPlane.addMetric('exceptions')
analyzorCrashinfo(lines, exceptionCrashinfo)

__builtin__.pwdManagement = MgmtPlane.addMetric('pwdMgmt')
analyzorPasswordManagement(lines, pwdManagement)

__builtin__.ManagementProtection = MgmtPlane.addMetric('MgmtPP')
analyzorMPP(lines, vtyList, vtyCfg, ManagementProtection)

__builtin__.tacacsPlusRedundant = MgmtPlane.addMetric('tacacsRedundant')
mode = 'RedundantAAA'
analyzorTacacs(lines, tacacsPlusRedundant, mode)

__builtin__.tacacsPlusAuth = MgmtPlane.addMetric('tacacsAuthentication')
mode = 'Authentication'
analyzorTacacs(lines, tacacsPlusAuth, mode)

__builtin__.tacacsPlusAuthorization = MgmtPlane.addMetric('tacacsAuthorization')
mode = 'Authorization'
analyzorTacacs(lines, tacacsPlusAuthorization, mode)

__builtin__.tacacsPlusAccounting = MgmtPlane.addMetric('tacacsAccounting')
mode = 'Accounting'
analyzorTacacs(lines, tacacsPlusAccounting, mode)

__builtin__.snmp = MgmtPlane.addMetric('snmp')
analyzorSNMP(lines, snmp)

__builtin__.syslog = MgmtPlane.addMetric('syslog')
analyzorSyslog(lines, syslog)

__builtin__.archive = MgmtPlane.addMetric('archive')
analyzorArchive(lines, archive)

icmpUnreachable = CtrlPlane.addMetric('icmpunreachable')
analyzorICMPUnreachable(icmpUnreachable, lines, ifaceCfg)

proxyArp = CtrlPlane.addMetric('proxyarp')
analyzorARPproxy(proxyArp, lines, ifaceCfg)

__builtin__.ntp = CtrlPlane.addMetric('ntp')
analyzorNtp(lines, ntp)

__builtin__.tcp = CtrlPlane.addMetric('tcp')
analyzorTcp(lines, tcp)

if __builtin__.deviceType  == 'router' or
    __builtin__.deviceType == 'both':
    
    __builtin__.bgp = CtrlPlane.addMetric('bgp')
    analyzorBgp(lines, bgp, aclIPv4)
    __builtin__.eigrp = CtrlPlane.addMetric('eigrp')
    analyzorEigrp(lines, eigrp, ifaceCfg)
    __builtin__.rip = CtrlPlane.addMetric('rip')
    analyzorRip(lines, rip, ifaceCfg)
    __builtin__.ospf = CtrlPlane.addMetric('ospf')
    analyzorOspf(lines, ospf, ifaceCfg)
    __builtin__.glbp = CtrlPlane.addMetric('glbp')
    analyzorGlbp(lines, glbp, ifaceCfg)
    __builtin__.hsrp = CtrlPlane.addMetric('hsrp')
    analyzorHsrp(lines, hsrp, ifaceCfg)
    __builtin__.vrrp = CtrlPlane.addMetric('vrrp')
    analyzorVrrp(lines, vrrp, ifaceCfg)
    icmpRedirects = DataPlane.addMetric('icmpredirects')
    analyzorICMPRedirects(icmpRedirects, lines, ifaceCfg)
    __builtin__.ipoptions = DataPlane.addMetric('ipoptions')
    analyzorIPoptions(lines, ipoptions)
    __builtin__.ipsrcroute = DataPlane.addMetric('ipsourceroute')
    analyzorIPsrcRoute(lines, ipsrcroute)
    __builtin__.denyicmp = DataPlane.addMetric('denyIcmpAnyAny')
    analyzorICMPdeny(lines, denyicmp)
    __builtin__.ipfrags = DataPlane.addMetric('IPfragments')
    analyzorIPfragments(lines, ipfrags)
    __builtin__.urpf = DataPlane.addMetric('urpf')
    analyzorURPF(lines, urpf, ifaceCfg)
    __builtin__.netflow = DataPlane.addMetric('netflow')
    analyzorNetflow(lines, netflow, ifaceCfg)

    if __builtin__.genericCfg.multicast == "Enabled":
        __builtin__.multicast = CtrlPlane.addMetric('multicast')
        analyzorMulticast(lines, multicast)

    if __builtin__.genericCfg.qos == "Enabled":
        __builtin__.qos = CtrlPlane.addMetric('qos')
        analyzorQos(lines, qos, ifaceCfg)

    if __builtin__.genericCfg.ipv6 == "Enabled":
        __builtin__.urpfv6 = DataPlane.addMetric('urpfv6')
        analyzorURPFv6(lines, urpfv6, ifaceCfg)

    if __builtin__.genericCfg.ipsec == "Enabled":
        __builtin__.ipsec = DataPlane.addMetric('ipsec')
        analyzorIPSEC(lines, ipsec)
    __builtin__.tclsh = CtrlPlane.addMetric('tclsh')
    analyzorTclSH(lines, tclsh)

if __builtin__.deviceType  == 'switch' or
    __builtin__.deviceType == 'both':
    
    __builtin__.portsecurity = DataPlane.addMetric('portsecurity')
    analyzorPortSecurity(lines, portsecurity, ifaceCfg)
    __builtin__.level2protocols = DataPlane.addMetric('level2protocols')
    analyzorLevel2Protocols(lines, level2protocols, ifaceCfg)

    if __builtin__.genericCfg.ipv6 == "Enabled":
        __builtin__.ipv6 = DataPlane.addMetric('ipv6')
        analyzorIPv6(lines, ipv6, aclIPv6, ifaceCfg)

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

print writeFooter()
