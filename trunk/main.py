#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-

from optparse import OptionParser
import sys
import __builtin__
import inspect
from common import *
from report import *
from metrics import *
from analyzor import *

# arguments parsing
parser = OptionParser()
parser.add_option("-c", "--config", dest="configurationFile", help ="Configuration file.")
parser.add_option("-t", "--template", dest="templateFile", help ="Template file.")
(options, args) = parser.parse_args()
if ( (len(sys.argv) <= 3) or (options.configurationFile == None) ):
	parser.error("no show run nor template file attached.")
	
preConf = readTemplate(options.templateFile)

__builtin__.iosVersion = float(removeString(preConf[0]))
configurationFile = options.configurationFile

__builtin__.outputType = preConf[1]
outputFile = preConf[2]
__builtin__.deviceType = preConf[3].lower()

__builtin__.macro = preConf[10]
__builtin__.ipv6TrustedPrefixes = preConf[11]

netManagement = preConf[7].split(',')
__builtin__.IPv4trustedNetManagementServers = list()
for entry in netManagement:
	entry = entry.split('/')
	if len(entry) == 1:
		entry.append('32')
	entry.append(dotted2Netmask(entry[1]))	
	entry.append(netmask2wildcard(entry[2]))
	entry.append(networkAddress(entry[0], entry[2]))
	__builtin__.IPv4trustedNetManagementServers.append(entry)

print writeHeader()

# configuration file reading

lines = readCfg(configurationFile)

__builtin__.genericCfg = addBasicInfo(lines)

# add metrics for the Management Plane
ManagementPlaneAudit = metrics()
# add metrics for the Management Plane
ControlPlaneAudit = CPmetrics()
# add metrics for the Management Plane
DataPlaneAudit = DPmetrics()
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

CdpProtocol = ManagementPlaneAudit.addMetric('cdp')
analyzorCdp(CdpProtocol, lines, ifaceCfg)

LldpProtocol = ManagementPlaneAudit.addMetric('lldp')
analyzorLldp(LldpProtocol, lines, ifaceCfg)

consoleCfg = parseConsole(lines)
__builtin__.console = ManagementPlaneAudit.addMetric('consolePort')
analyzorConsole(consoleCfg, console, lines)

auxCfg = parseAux(lines)
__builtin__.aux = ManagementPlaneAudit.addMetric('auxPort')
analyzorAux(auxCfg,aux)

vtyCfg = parseVty(lines)
__builtin__.vtyList = []
for i in range (0, len(vtyCfg)):
	__builtin__.vtyList.append(ManagementPlaneAudit.addMetric('vtyPort'))
	__builtin__.vtyList[i].sessionNumbers = vtyCfg[i][0].split(' ')[2:]
for i in range(0, len(vtyList)):
	analyzorVty(vtyCfg[i],vtyList[i])	

bannerMotd = parseBannerMOTD(lines)
__builtin__.motd = ManagementPlaneAudit.addMetric('BannerMotd')
analyzorBanner(bannerMotd, motd, 0)

bannerLogin = parseBannerLOGIN(lines)
__builtin__.banLogin = ManagementPlaneAudit.addMetric('BannerLogin')
analyzorBanner(bannerLogin, banLogin, 1)

bannerExec = parseBannerEXEC(lines)
__builtin__.banExec = ManagementPlaneAudit.addMetric('BannerExec')
analyzorBanner(bannerExec, banExec, 2)

__builtin__.genericServices = ManagementPlaneAudit.addMetric('genericServices')
analyzorServices(lines, genericServices)

__builtin__.memoryCpu = ManagementPlaneAudit.addMetric('memCpu')
analyzorMemCpu(lines, memoryCpu)

__builtin__.exceptionCrashinfo = ManagementPlaneAudit.addMetric('exceptions')
analyzorCrashinfo(lines, exceptionCrashinfo)

__builtin__.pwdManagement = ManagementPlaneAudit.addMetric('pwdMgmt')
analyzorPasswordManagement(lines, pwdManagement)

__builtin__.ManagementProtection = ManagementPlaneAudit.addMetric('MgmtPP')
analyzorMPP(lines, vtyList, vtyCfg, ManagementProtection)

__builtin__.tacacsPlusRedundant = ManagementPlaneAudit.addMetric('tacacsRedundant')
mode = 'RedundantAAA'
analyzorTacacs(lines, tacacsPlusRedundant, mode)

__builtin__.tacacsPlusAuth = ManagementPlaneAudit.addMetric('tacacsAuthentication')
mode = 'Authentication'
analyzorTacacs(lines, tacacsPlusAuth, mode)

__builtin__.tacacsPlusAuthorization = ManagementPlaneAudit.addMetric('tacacsAuthorization')
mode = 'Authorization'
analyzorTacacs(lines, tacacsPlusAuthorization, mode)

__builtin__.tacacsPlusAccounting = ManagementPlaneAudit.addMetric('tacacsAccounting')
mode = 'Accounting'
analyzorTacacs(lines, tacacsPlusAccounting, mode)

__builtin__.snmp = ManagementPlaneAudit.addMetric('snmp')
analyzorSNMP(lines, snmp)

__builtin__.syslog = ManagementPlaneAudit.addMetric('syslog')
analyzorSyslog(lines, syslog)

__builtin__.archive = ManagementPlaneAudit.addMetric('archive')
analyzorArchive(lines, archive)

icmpUnreachable = ControlPlaneAudit.addMetric('icmpunreachable')
analyzorICMPUnreachable(icmpUnreachable, lines, ifaceCfg)

proxyArp = ControlPlaneAudit.addMetric('proxyarp')
analyzorARPproxy(proxyArp, lines, ifaceCfg)

__builtin__.ntp = ControlPlaneAudit.addMetric('ntp')
analyzorNtp(lines, ntp)

__builtin__.tcp = ControlPlaneAudit.addMetric('tcp')
analyzorTcp(lines, tcp)

if __builtin__.deviceType == 'router' or __builtin__.deviceType == 'both':
	__builtin__.bgp = ControlPlaneAudit.addMetric('bgp')
	analyzorBgp(lines, bgp)

	__builtin__.eigrp = ControlPlaneAudit.addMetric('eigrp')
	analyzorEigrp(lines, eigrp, ifaceCfg)

	__builtin__.rip = ControlPlaneAudit.addMetric('rip')
	analyzorRip(lines, rip, ifaceCfg)

	__builtin__.ospf = ControlPlaneAudit.addMetric('ospf')
	analyzorOspf(lines, ospf, ifaceCfg)
	
	__builtin__.glbp = ControlPlaneAudit.addMetric('glbp')
	analyzorGlbp(lines, glbp, ifaceCfg)

	__builtin__.hsrp = ControlPlaneAudit.addMetric('hsrp')
	analyzorHsrp(lines, hsrp, ifaceCfg)
	
	__builtin__.vrrp = ControlPlaneAudit.addMetric('vrrp')
	analyzorVrrp(lines, vrrp, ifaceCfg)

	icmpRedirects = DataPlaneAudit.addMetric('icmpredirects')
	analyzorICMPRedirects(icmpRedirects, lines, ifaceCfg)

	__builtin__.ipoptions = DataPlaneAudit.addMetric('ipoptions')
	analyzorIPoptions(lines, ipoptions)

	__builtin__.ipsrcroute = DataPlaneAudit.addMetric('ipsourceroute')
	analyzorIPsrcRoute(lines, ipsrcroute)

	__builtin__.denyicmp = DataPlaneAudit.addMetric('denyIcmpAnyAny')
	analyzorICMPdeny(lines, denyicmp)

	__builtin__.ipfrags = DataPlaneAudit.addMetric('IPfragments')
	analyzorIPfragments(lines, ipfrags)

	__builtin__.urpf = DataPlaneAudit.addMetric('urpf')
	analyzorURPF(lines, urpf, ifaceCfg)

	__builtin__.netflow = DataPlaneAudit.addMetric('netflow')
	analyzorNetflow(lines, netflow, ifaceCfg)

	if __builtin__.genericCfg.multicast == "Enabled":
		__builtin__.multicast = ControlPlaneAudit.addMetric('multicast')
		analyzorMulticast(lines, multicast)

	if __builtin__.genericCfg.qos == "Enabled":
		__builtin__.qos = DataPlaneAudit.addMetric('qos')
		analyzorQos(lines, qos, ifaceCfg)

	if __builtin__.genericCfg.ipv6 == "Enabled":
		__builtin__.urpfv6 = DataPlaneAudit.addMetric('urpfv6')
		analyzorURPFv6(lines, urpfv6, ifaceCfg)

	if __builtin__.genericCfg.ipsec == "Enabled":
		__builtin__.ipsec = DataPlaneAudit.addMetric('ipsec')
		analyzorIPSEC(lines, ipsec)		
	__builtin__.tclsh = ControlPlaneAudit.addMetric('tclsh')
	analyzorTclSH(lines, tclsh)

if __builtin__.deviceType == 'switch' or __builtin__.deviceType == 'both':
	__builtin__.portsecurity = DataPlaneAudit.addMetric('portsecurity')
	analyzorPortSecurity(lines, portsecurity, ifaceCfg)
	__builtin__.level2protocols = DataPlaneAudit.addMetric('level2protocols')
	analyzorLevel2Protocols(lines, level2protocols, ifaceCfg)
	
	if __builtin__.genericCfg.ipv6 == "Enabled":
		__builtin__.ipv6 = DataPlaneAudit.addMetric('ipv6')
		analyzorIPv6(lines, ipv6, aclIPv6, ifaceCfg)		
	
output = {
	'stdout': lambda : stdoutReport(genericCfg, ManagementPlaneAudit.metricsList, ControlPlaneAudit.metricsList, DataPlaneAudit.metricsList),
	'csv': lambda : csvReport(outputFile, ManagementPlaneAudit.metricsList, ControlPlaneAudit.metricsList, DataPlaneAudit.metricsList),
	'html': lambda : htmlReport(outputFile, genericCfg, ManagementPlaneAudit.metricsList, ControlPlaneAudit.metricsList, DataPlaneAudit.metricsList),
	'pdf': lambda : pdfReport(outputFile, genericCfg, ManagementPlaneAudit.metricsList, ControlPlaneAudit.metricsList, DataPlaneAudit.metricsList) 
	}[outputType]()

print writeFooter()
