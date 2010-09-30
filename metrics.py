# -*- coding: iso-8859-15 -*-

from common import *
import __builtin__

class metrics:
	
	metricsList = list()
	
	def __init__(self):
		pass
	
	def addMetric(self,metricName):
		if metricName == 'cdp':
			metricAdded = cdp()
		if metricName == 'lldp':
			metricAdded = lldp()
		if metricName == 'archive':
			metricAdded = ArchiveConfiguration()
		if metricName == 'syslog':
			metricAdded = Syslog()
		if metricName == 'snmp':
			metricAdded = Snmp()
		if metricName == 'tacacsRedundant':
			metricAdded = tacacsRedun()
		if metricName == 'tacacsAuthentication':
			metricAdded = tacacsAuth()
		if metricName == 'tacacsAuthorization':
			metricAdded = tacacsAuthorization()
		if metricName == 'tacacsAccounting':
			metricAdded = tacacsAccounting()
		if metricName == 'BannerMotd':
			metricAdded = motdBanner()
		if metricName == 'BannerLogin':
			metricAdded = loginBanner()
		if metricName == 'BannerExec':
			metricAdded = execBanner()						
		if metricName == 'pwdMgmt':
			metricAdded = passwordManagement()
		if metricName == 'MgmtPP':
			metricAdded = managementProtection()
		if metricName == 'exceptions':
			metricAdded = exceptionCrash()
		if metricName == 'memCpu':
			metricAdded = memCpu()
		if metricName == 'genericServices':
			metricAdded = globalServices()
		if metricName == 'consolePort':
			metricAdded = lineConsole()
		if metricName == 'auxPort':
			metricAdded = lineAux()
		if metricName == 'vtyPort':
			metricAdded = lineVty()
		self.metricsList.append(metricAdded)	
		return metricAdded
	
#	def addInterface(self,metricName, name):
#		if metricName == 'interface':
#			metricAdded = interfaces()
#			metricAdded.name = name
#		self.metricsList.append(metricName)	
#		return metricAdded	
		

	def listMetric(self):
		return self.metricsList

class IFSmetrics:
	def __init__(self):
		pass	 
	def addInterface(self,metricName, name):
		if metricName == 'interface':
			metricAdded = interfaces()
			metricAdded.name = name
		return metricAdded	

class ACLV4metrics:
	def __init__(self):
		pass	 
	def addInterface(self,metricName, name):
		if metricName == 'aclv4':
			metricAdded = ACLv4()
			metricAdded.name = name
		return metricAdded
	
class ACLV6metrics:
	def __init__(self):
		pass	 
	def addInterface(self,metricName, name):
		if metricName == 'aclv6':
			metricAdded = ACLv6()
			metricAdded.name = name
		return metricAdded

class CPmetrics:
	
	metricsList = list()
	
	def __init__(self):
		pass
	
	def addMetric(self,metricName):
		if metricName == 'icmpredirects':
			metricAdded = IPicmpRedirects()
		if metricName == 'icmpunreachable':
			metricAdded = IPicmpUnreachable()
		if metricName == 'proxyarp':
			metricAdded = ARPproxy()
		if metricName == 'ntp':
			metricAdded = Ntp()
		if metricName == 'bgp':
			metricAdded = Bgp()
		if metricName == 'eigrp':
			metricAdded = Eigrp()
		if metricName == 'rip':
			metricAdded = Rip()
		if metricName == 'ospf':
			metricAdded = Ospf()
		if metricName == 'glbp':
			metricAdded = Glbp()
		if metricName == 'hsrp':
			metricAdded = Hsrp()
		if metricName == 'vrrp':
			metricAdded = Vrrp()						
		if metricName == 'tclsh':
			metricAdded = TclSH()
		if metricName == 'tcp':
			metricAdded = Tcp()			
		if metricName == 'multicast':
			metricAdded = Multicast()
		if metricName == 'qos':
			metricAdded = Qos()			
		self.metricsList.append(metricAdded)	
		return metricAdded
	
	def addInterface(self,metricName, name):
		if metricName == 'interface':
			metricAdded = interfaces()
			metricAdded.name = name
		self.metricsList.append(metricName)	
		return metricAdded	
	

	def listMetric(self):
		return self.metricsList


class DPmetrics:
	
	metricsList = list()
	
	def __init__(self):
		pass
	
	def addMetric(self,metricName):
		if metricName == 'icmpredirects':
			metricAdded = IPicmpRedirects()
		if metricName == 'ipoptions':
			metricAdded = IPoptions()
		if metricName == 'ipsourceroute':
			metricAdded = IPsourceRoute()
		if metricName == 'denyIcmpAnyAny':
			metricAdded = ICMPdeny()
		if metricName == 'IPfragments':
			metricAdded = IPfrags()
		if metricName == 'urpf':
			metricAdded = URPF()
		if metricName == 'urpfv6':
			metricAdded = URPFv6()
		if metricName == 'portsecurity':
			metricAdded = PortSecurity()
		if metricName == 'ipv6':
			metricAdded = IPv6()
		if metricName == 'ipsec':
			metricAdded = IPSEC()
		if metricName == 'level2protocols':
			metricAdded = dtpstpvlan()			
		if metricName == 'netflow':
			metricAdded= Netflow()
		self.metricsList.append(metricAdded)	
		return metricAdded
	
	def addInterface(self,metricName, name):
		if metricName == 'interface':
			metricAdded = interfaces()
			metricAdded.name = name
		self.metricsList.append(metricName)	
		return metricAdded	
	

	def listMetric(self):
		return self.metricsList

		
class interfaces:
	def __init__(self):
		self.name = ''
		self.ipAddress = 'no ip address'
		self.ShutdownState = 'no shutdown'
		self.configuration = []
		
		
	def populateMetricsFromConfig(self):
		for line in range (0, len(self.configuration)):
			if self.configuration[line].startswith('ip address'):
				self.ipAddress = self.configuration[line]
			if self.configuration[line].startswith('no ip address'):
				self.ipAddress = self.configuration[line]
			if self.configuration[line].startswith('shutdown'):
				self.ShutdownState = 'shutdown'		
					
class ACLv4:
	def __init__(self):
		self.name = ''
		self.type = ''		
		self.configuration = []
		
	def populateMetricsFromConfig(self):
		for line in range (0, len(self.configuration)):
			if self.configuration[line].startswith('ip access-list'):
				#self.name = self.configuration[line].split(' ')[3]
				self.type = self.configuration[line].split(' ')[2]
				

class ACLv6:
	def __init__(self):
		self.name = ''
		self.configuration = []
		
	def populateMetricsFromConfig(self):
		for line in range (0, len(self.configuration)):
			if self.configuration[line].startswith('ipv6 access-list'):
				self.name = self.configuration[line].split[' '][2]

class lineConsole:
	def __init__(self):
		self.metricName = 'Console'
		self.longName = 'Console port'
		self.password = None
		self.execTimeout = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.privilegezero = {
		"cmdInCfg": (None),
		"loginlocal": (None),
		"globalusername": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}		

class lineAux:
	def __init__(self):
		self.password = None
		self.metricName = 'Aux'
		self.longName = 'Aux port'
		self.execTimeout = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.transportInput = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}		
		self.transportOutput = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.noExec = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}			

class lineVty:
	def __init__(self):
		self.metricName = 'Vty'
		self.longName = 'Vty lines'
		self.password = None
		self.sessionNumbers = None
		self.execTimeout = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.transportInput = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.transportOutput = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.IPv6accessClass = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}		

class motdBanner:
	def __init__(self):
		self.metricName = 'motdBanner'
		self.longName = 'MOTD banner'
		self.configured = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}	
		self.routerName = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		
class execBanner:
	def __init__(self):
		self.metricName = 'execBanner'
		self.longName = 'EXEC banner'
		self.configured = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}	
		self.routerName = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		
class loginBanner:
	def __init__(self):
		self.metricName = 'loginBanner'
		self.longName = 'LOGIN banner'
		self.configured = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}	
		self.routerName = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}			
					
class globalServices:
	def __init__(self):
		self.metricName = 'globalServices'
		self.longName = 'IOS TCP/UDP services'
		self.pwdRecovery = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.tcpSmallServers = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.udpSmallServers = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.serviceFinger = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.serviceBootpServer = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.serviceTcpKeepAliveIn = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.serviceTcpKeepAliveOut = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.serviceIpDhcpBootIgnore = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.serviceDhcp = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.Mop = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}		
		self.ipDomainLookup = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.servicePad = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.serviceHttpServer = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}					
		self.serviceHttpsServer = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.serviceConfig = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

class memCpu:
	def __init__(self):
		self.metricName = 'memCpu'
		self.longName = 'CPU/Memory'
		self.schedulerallocate = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.schedulerinterval = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}		
		self.lowWatermarkProcessor = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.lowWatermarkIo = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.memReserveCritical = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.memReserveConsole = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.memIgnoreOverflowIo = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		
		self.memIgnoreOverflowCpu = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}				
		self.cpuThresholdNotice = {
		"cmdSnmpServerTraps": (None),
		"cmdSnmpServerHost": (None),
		"cmdCpuThreshold": (None),
		"cmdCpuStats": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}		

class exceptionCrash:
	def __init__(self):
		self.metricName = 'exceptionCrash'
		self.longName = 'Exceptions/crashes'	
		self.crashinfoMaxFiles = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

class managementProtection:
	def __init__(self):
		self.metricName = 'managementProtection'
		self.longName = 'Management protection'	
		self.managementInterface = {
		"cpHostCfg": (None),
		"mgmtIfaceCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.sshServerTimeout = {
		"timeout": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.sshServerAuthRetries = {
		"authRetries": (None),
		"sourceInterface": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.sshServerSourceInterface = {
		"sourceInterface": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

		self.scpServer = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.httpSecureServer = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}		
		self.loginbruteforce = {
		"blockfor": (None),
		"delay": (None),
		"quietacl": (None),
		"faillog": (None),
		"successlog": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

class tacacsRedun:
	def __init__(self):
		self.metricName = 'tacacsRedundant'
		self.longName = 'Tacacs+ servers redundancy'
		self.redundant = {
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

class tacacsAuth:
	def __init__(self):
		self.metricName = 'tacacsAuthentication'
		self.longName = 'Tacacs+ authentication'
		self.aaaNewModel = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.authTacacs = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.authFallback = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}		

class tacacsAuthorization:
	def __init__(self):
		self.metricName = 'tacacsAuthorization'
		self.longName = 'Tacacs+ authorization'
		self.aaaNewModel = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.authExec = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.level0 = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.level1 = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.level15 = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}				
		
class tacacsAccounting:
	def __init__(self):
		self.metricName = 'tacacsAccounting'
		self.longName = 'Tacacs+ accounting'
		self.aaaNewModel = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.authAccounting = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.level0 = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.level1 = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.level15 = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}				

		
class passwordManagement:
	def __init__(self):
		self.metricName = 'passwordManagement'
		self.longName = 'Passwords and authentication management'
		self.enableSecret = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.svcPwdEncryption = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.usernameSecret = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.retryLockout = {
		"aaaNewModel": (None),
		"usernames": (None),
		"maxFail": (None),
		"aaaAuthLoginLocal": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
				
class cdp:
	def __init__(self):
		self.metricName = 'cdp'
		self.longName = 'CDP'
		self.cdp = {
		"globalCdp": True,
		"disabledIfsCdp": [],
		"enabledIfsCdp": [],
		"mustBeReported": False,
		"fixImpact": None,
		"definition": None,
		"threatInfo": None,
		"howtofix": None,
		"cvss": None}				

class lldp:
	def __init__(self):
		self.metricName = 'lldp'
		self.longName = 'LLDP'
		self.lldp = {
		"globalLldp": True,
		"enabledTransmitLldp": [],
		"enabledReceiveLldp": [],
		"disabledIfsLldp": [],
		"mustBeReported": False,
		"fixImpact": None,
		"definition": None,
		"threatInfo": None,
		"howtofix": None,
		"cvss": None}	
		
		
class Snmp:
	def __init__(self):
		self.metricName = 'snmp'
		self.longName = 'SNMP'
		self.ROcommunity = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.ROcommunityACL = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

		self.RWcommunity = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.RWcommunityACL = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.ViewROcommunity = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.ViewROcommunityACL = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

		self.ViewRWcommunity = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.ViewRWcommunityACL = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.snmpV3 = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		
class Syslog:
	def __init__(self):
		self.metricName = 'syslog'
		self.longName = 'Syslog'
		self.Server = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.levelTrap = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.levelBuffered = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.loggingConsole = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.loggingMonitor = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}				
		self.loggingBuffered = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.Interface = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.timestamp = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.serverarp = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		
class ArchiveConfiguration:
	def __init__(self):
		self.metricName = 'archive'
		self.longName = 'Configuration Replace/Rollback'
		self.configuration = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}		
		self.exclusive = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.secureBoot = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}					
		self.secureConfig = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.logs = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		
class IPicmpRedirects:
	def __init__(self):
		self.metricName = 'icmpRedirects'
		self.longName = 'ICMPv4 redirects'
		self.redirects = {
		"disabledIfsFeature": [],
		"enabledIfsFeature": [],
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"cvss": (None)
		}
		
class IPicmpUnreachable:
	def __init__(self):
		self.metricName = 'icmpUnreachable'
		self.longName = 'ICMPv4 unreachable'
		self.unreachable = {
		"unreachableRate": None,
		"disabledIfsFeature": [],
		"enabledIfsFeature": [],
		"mustBeReported": False,
		"fixImpact": None,
		"definition": None,
		"threatInfo": None,
		"howtofix": None,
		"cvss": None}


class ARPproxy:
	def __init__(self):
		self.metricName = 'proxyArp'
		self.longName = 'ARP proxy'
		self.proxy = {
		"disabledIfsFeature": [],
		"enabledIfsFeature": [],
		"mustBeReported": False,
		"fixImpact": None,
		"definition": None,
		"threatInfo": None,
		"howtofix": None,
		"cvss": None}


class Ntp:
	def __init__(self):
		self.metricName = 'ntp'
		self.longName = 'NTP'
		self.authentication = {
		"authenticate": (None),
		"key": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
class Bgp:
	def __init__(self):
		self.metricName = 'bgp'
		self.longName = 'BGP'
		self.ttlSecurity = {
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.sessionPassword = {
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.maxPrefixes = {
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}		
		self.prefixList = {
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.aspathList = {
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		
class Eigrp:
	def __init__(self):
		self.metricName = 'eigrp'
		self.longName = 'EIGRP'
		self.asNumber = []
		self.activeIfaces = []
		self.passiveDefault = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"asn": [],
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.authModeMD5 = {
		"cmdInCfg": (None),
		"interfaces": [],
		"asn": [],
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.routeFilteringIn = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"asn": [],
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}		
		self.routeFilteringOut = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"asn": [],
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

class Rip:
	def __init__(self):
		self.metricName = 'rip'
		self.longName = 'RIP'
		self.version = None
		self.authModeMD5 = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"interfaces": [],
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

class Ospf:
	def __init__(self):
		self.metricName = 'ospf'
		self.longName = 'OSPF'
		self.area = []
		self.passiveDefault = {
		"pid": [],
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}		
		self.authModeMD5 = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"pid": [],
		"area": [],
		"interfaces": [],
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.routeFilteringIn = {
		"cmdInCfg": (None),
		"area": [],
		"pid": [],
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.routeFilteringOut = {
		"cmdInCfg": (None),
		"area": [],
		"pid": [],
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.maxLSA = {
		"pid": [],
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

class Glbp:
	def __init__(self):
		self.metricName = 'glbp'
		self.longName = 'GLBP'
		self.authModeMD5 = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

class Hsrp:
	def __init__(self):
		self.metricName = 'hsrp'
		self.longName = 'HSRP'
		self.authModeMD5 = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		
class Vrrp:
	def __init__(self):
		self.metricName = 'vrrp'
		self.longName = 'VRRP'
		self.authModeMD5 = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}		

class IPoptions:
	def __init__(self):
		self.metricName = 'ipoptions'
		self.longName = 'IPv4 Options'
		self.drop = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}		

class IPsourceRoute:
	def __init__(self):
		self.metricName = 'ipsourceroute'
		self.longName = 'IPv4 source route'
		self.drop = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}		

class ICMPdeny:
	def __init__(self):
		self.metricName = 'icmpdeny'
		self.longName = 'ICMP deny any any'
		self.filtered = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

class IPfrags:
	def __init__(self):
		self.metricName = 'ipfrags'
		self.longName = 'IPv4 fragments'
		self.filtered = {
		"tcp": (None),
		"udp": (None),
		"icmp": (None),
		"ip": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

class URPF:
	def __init__(self):
		self.metricName = 'urpf'
		self.longName = 'Unicast Reverse Path Forwarding (IPv4)'
		self.spoofing = {
		"candidates": [],
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

class URPFv6:
	def __init__(self):
		self.metricName = 'urpfv6'
		self.longName = 'Unicast Reverse Path Forwarding (IPv6)'
		self.spoofing = {
		"candidates": [],
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		
class PortSecurity:
	def __init__(self):
		self.metricName = 'portsecurity'
		self.longName = 'Port Security'
		self.sticky = {
		"candidates": [],
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}		
		self.violation = {
		"candidates": [],
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}		
		self.maximumTotal = {
		"candidates": [],
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.maximumAccess = {
		"candidates": [],
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.maximumVoice = {
		"candidates": [],
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

class IPv6:
	def __init__(self):
		self.metricName = 'ipv6'
		self.longName = 'IPv6'
		self.rh0 = {
		"Notfiltered": [],
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

class IPSEC:
	def __init__(self):
		self.metricName = 'ipsec'
		self.longName = 'IPSEC'
		self.cacIKE = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.cacRSC = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		
class TclSH:
	def __init__(self):
		self.metricName = 'tclsh'
		self.longName = 'TCLSH shell scripting'
		self.shell = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

class Tcp:
	def __init__(self):
		self.metricName = 'tcp'
		self.longName = 'TCP'
		self.synwait = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

class dtpstpvlan:
	def __init__(self):
		self.metricName = 'level2protocols'
		self.longName = 'Level 2'
		self.nonegotiate = {
		"candidates": [],
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}		
		self.flowcontrol = {
		"candidates": [],
		"receive": (None),
		"transmit": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.udld = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.vlan1 = {
		"candidates": [],
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.unusedports = {
		"candidates": [],
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}		
		self.vtpsecure = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.bpduguard = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.stproot = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
		self.dot1x = {
		"cmdInCfg": (None),
		"mustBeReported": False,
		"fixImpact": (None),
		"definition": (None),
		"desc": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

class Netflow:
	def __init__(self):
		self.metricName = 'Netflow'
		self.longName = 'Netflow'
		self.V9securityL2 = {
		"fragoffset": (None),
		"icmp": (None),
		"ipid": (None),
		"macaddr": (None),
		"packetlen": (None),
		"ttl": (None),
		"vlid": (None),
		"interfacegress": False,									
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}

class Multicast:
	def __init__(self):
		self.metricName = 'Multicast'
		self.longName = 'Multicast'
		self.msdp = {
		"safilterin": (None),
		"safilterout": (None),
		"redistributelist": (None),		
		"mustBeReported": False,
		"desc": (None),
		"fixImpact": (None),
		"definition": (None),
		"threatInfo": (None),
		"howtofix": (None),
		"upgrade": (None),
		"cvss": (None)
		}
class Qos:
	def __init__(self):
		self.metricName = 'Qos'
		self.longName = 'Qos'
