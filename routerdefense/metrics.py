# -*- coding: iso-8859-1 -*-

from common import *
import __builtin__

class metrics:

    metrics_list = list()

    def __init__(self):
        pass

    def add(self,metric_name):
        if metric_name == 'cdp':
            metric = cdp()
        if metric_name == 'lldp':
            metric = lldp()
        if metric_name == 'archive':
            metric = ArchiveConfiguration()
        if metric_name == 'syslog':
            metric = Syslog()
        if metric_name == 'snmp':
            metric = Snmp()
        if metric_name == 'tacacsRed':
            metric = tacacsRedun()
        if metric_name == 'tacacsThe':
            metric = tacacsAuth()
        if metric_name == 'tacacsTho':
            metric = tacacsAuthorization()
        if metric_name == 'tacacsAcc':
            metric = tacacsAccounting()
        if metric_name == 'BannerMotd':
            metric = motdBanner()
        if metric_name == 'BannerLogin':
            metric = loginBanner()
        if metric_name == 'BannerExec':
            metric = execBanner()
        if metric_name == 'pwdMgmt':
            metric = passwordManagement()
        if metric_name == 'MgmtPP':
            metric = managementProtection()
        if metric_name == 'exceptions':
            metric = exceptionCrash()
        if metric_name == 'memCpu':
            metric = memCpu()
        if metric_name == 'genSvcs':
            metric = globalServices()
        if metric_name == 'consolePort':
            metric = lineConsole()
        if metric_name == 'auxPort':
            metric = lineAux()
        if metric_name == 'vtyPort':
            metric = lineVty()
        self.metrics_list.append(metric)
        return metric

    def list_metric(self):
        return self.metrics_list

class IFSmetrics:
    def __init__(self):
        pass
    def add_if(self,metric_name, name):
        if metric_name == 'interface':
            metric = interfaces()
            metric.name = name
        return metric

class ACLV4metrics:
    def __init__(self):
        pass
    def add(self,metric_name, name):
        if metric_name == 'aclv4':
            metric = ACLv4()
            metric.name = name
        return metric

class ACLV6metrics:
    def __init__(self):
        pass
    def add(self,metric_name, name):
        if metric_name == 'aclv6':
            metric = ACLv6()
            metric.name = name
        return metric

class CPmetrics:

    metrics_list = list()

    def __init__(self):
        pass

    def add(self,metric_name):
        if metric_name == 'icmpredirects':
            metric = IPicmpRedirects()
        if metric_name == 'icmpunreach':
            metric = IPicmpUnreachable()
        if metric_name == 'proxyarp':
            metric = ARPproxy()
        if metric_name == 'ntp':
            metric = Ntp()
        if metric_name == 'bgp':
            metric = Bgp()
        if metric_name == 'eigrp':
            metric = Eigrp()
        if metric_name == 'rip':
            metric = Rip()
        if metric_name == 'ospf':
            metric = Ospf()
        if metric_name == 'glbp':
            metric = Glbp()
        if metric_name == 'hsrp':
            metric = Hsrp()
        if metric_name == 'vrrp':
            metric = Vrrp()
        if metric_name == 'tclsh':
            metric = TclSH()
        if metric_name == 'tcp':
            metric = Tcp()
        if metric_name == 'multicast':
            metric = Multicast()
        if metric_name == 'qos':
            metric = Qos()
        self.metrics_list.append(metric)
        return metric

    def add_if(self,metric_name, name):
        if metric_name == 'interface':
            metric = interfaces()
            metric.name = name
        self.metrics_list.append(metric_name)
        return metric


    def list_metric(self):
        return self.metrics_list


class DPmetrics:

    metrics_list = list()

    def __init__(self):
        pass

    def add(self,metric_name):
        if metric_name == 'icmpredirects':
            metric = IPicmpRedirects()
        if metric_name == 'ipoptions':
            metric = IPoptions()
        if metric_name == 'ipsourceroute':
            metric = IPsourceRoute()
        if metric_name == 'denyIcmpAnyAny':
            metric = ICMPdeny()
        if metric_name == 'IPfragments':
            metric = IPfrags()
        if metric_name == 'urpf':
            metric = URPF()
        if metric_name == 'urpfv6':
            metric = URPFv6()
        if metric_name == 'portsecurity':
            metric = PortSecurity()
        if metric_name == 'ipv6':
            metric = IPv6()
        if metric_name == 'ipsec':
            metric = IPSEC()
        if metric_name == 'l2protos':
            metric = dtpstpvlan()
        if metric_name == 'netflow':
            metric= Netflow()
        self.metrics_list.append(metric)
        return metric

    def add_if(self,metric_name, name):
        if metric_name == 'interface':
            metric = interfaces()
            metric.name = name
        self.metrics_list.append(metric_name)
        return metric


    def list_metric(self):
        return self.metrics_list


class interfaces:
    def __init__(self):
        self.name = ''
        self.ip_address = 'no ip address'
        self.shutdown_state = 'no shutdown'
        self.configuration = []

    def get_metrics_from_config(self):
        for line in range (0, len(self.configuration)):
            if self.configuration[line].startswith('ip address'):
                self.ip_address = self.configuration[line]
            if self.configuration[line].startswith('no ip address'):
                self.ip_address = self.configuration[line]
            if self.configuration[line].startswith('shutdown'):
                self.shutdown_state = 'shutdown'

class ACLv4:
    def __init__(self):
        self.name = ''
        self.type = ''
        self.configuration = []

    def get_metrics_from_config(self):
        for line in range (0, len(self.configuration)):
            if self.configuration[line].startswith('ip access-list'):
                #self.name = self.configuration[line].split(' ')[3]
                self.type = self.configuration[line].split(' ')[2]


class ACLv6:
    def __init__(self):
        self.name = ''
        self.configuration = []

    def get_metrics_from_config(self):
        for line in range (0, len(self.configuration)):
            if self.configuration[line].startswith('ipv6 access-list'):
                self.name = self.configuration[line].split[' '][2]

class lineConsole:
    def __init__(self):
        self.metric_name = 'Console'
        self.long_name = 'Console port'
        self.password = None
        self.execTimeout = {
        "cmdInCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        self.metric_name = 'Aux'
        self.long_name = 'Aux port'
        self.execTimeout = {
        "cmdInCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        self.metric_name = 'Vty'
        self.long_name = 'Vty lines'
        self.password = None
        self.sessionNumbers = None
        self.execTimeout = {
        "cmdInCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "desc": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.IPv4accessClass = {
        "cmdInCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        self.metric_name = 'motdBanner'
        self.long_name = 'MOTD banner'
        self.configured = {
        "cmdInCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        self.metric_name = 'execBanner'
        self.long_name = 'EXEC banner'
        self.configured = {
        "cmdInCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        self.metric_name = 'loginBanner'
        self.long_name = 'LOGIN banner'
        self.configured = {
        "cmdInCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        self.metric_name = 'globalServices'
        self.long_name = 'IOS TCP/UDP services'
        self.pwdRecovery = {
        "cmdInCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.serviceBootpServer = {
        "cmdInCfg": (None),
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.serviceTcpKeepAliveIn = {
        "cmdInCfg": (None),
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.serviceTcpKeepAliveOut = {
        "cmdInCfg": (None),
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.serviceIpDhcpBootIgnore = {
        "cmdInCfg": (None),
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.serviceDhcp = {
        "cmdInCfg": (None),
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.Mop = {
        "cmdInCfg": (None),
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.ipDomainLookup = {
        "cmdInCfg": (None),
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.servicePad = {
        "cmdInCfg": (None),
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.serviceHttpServer = {
        "cmdInCfg": (None),
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.serviceHttpsServer = {
        "cmdInCfg": (None),
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.serviceConfig = {
        "cmdInCfg": (None),
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }

class memCpu:
    def __init__(self):
        self.metric_name = 'memCpu'
        self.long_name = 'CPU/Memory'
        self.schedulerallocate = {
        "cmdInCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        self.metric_name = 'exceptionCrash'
        self.long_name = 'Exceptions/crashes'
        self.crashinfoMaxFiles = {
        "cmdInCfg": (None),
        "must_report": False,
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
        self.metric_name = 'managementProtection'
        self.long_name = 'Management protection'
        self.managementInterface = {
        "cpHostCfg": (None),
        "mgmtIfaceCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        self.metric_name = 'tacacsRedundant'
        self.long_name = 'Tacacs+ servers redundancy'
        self.redundant = {
        "must_report": False,
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
        self.metric_name = 'tacacsAuthentication'
        self.long_name = 'Tacacs+ authentication'
        self.aaaNewModel = {
        "cmdInCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        self.metric_name = 'tacacsAuthorization'
        self.long_name = 'Tacacs+ authorization'
        self.aaaNewModel = {
        "cmdInCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        self.metric_name = 'tacacsAccounting'
        self.long_name = 'Tacacs+ accounting'
        self.aaaNewModel = {
        "cmdInCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        self.metric_name = 'passwordManagement'
        self.long_name = 'Passwords and authentication management'
        self.enableSecret = {
        "cmdInCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        self.metric_name = 'cdp'
        self.long_name = 'CDP'
        self.cdp = {
        "globalCdp": True,
        "disabledIfsCdp": [],
        "enabledIfsCdp": [],
        "must_report": False,
        "fixImpact": None,
        "definition": None,
        "threatInfo": None,
        "howtofix": None,
        "cvss": None}

class lldp:
    def __init__(self):
        self.metric_name = 'lldp'
        self.long_name = 'LLDP'
        self.lldp = {
        "globalLldp": True,
        "enabledTransmitLldp": [],
        "enabledReceiveLldp": [],
        "disabledIfsLldp": [],
        "must_report": False,
        "fixImpact": None,
        "definition": None,
        "threatInfo": None,
        "howtofix": None,
        "cvss": None}


class Snmp:
    def __init__(self):
        self.metric_name = 'snmp'
        self.long_name = 'SNMP'
        self.ROcommunity = {
        "cmdInCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        self.metric_name = 'syslog'
        self.long_name = 'Syslog'
        self.Server = {
        "cmdInCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        self.metric_name = 'archive'
        self.long_name = 'Configuration Replace/Rollback'
        self.configuration = {
        "cmdInCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        self.metric_name = 'icmpRedirects'
        self.long_name = 'ICMPv4 redirects'
        self.redirects = {
        "disabledIfsFeature": [],
        "enabledIfsFeature": [],
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "cvss": (None)
        }

class IPicmpUnreachable:
    def __init__(self):
        self.metric_name = 'icmpUnreachable'
        self.long_name = 'ICMPv4 unreachable'
        self.unreachable = {
        "unreachableRate": None,
        "disabledIfsFeature": [],
        "enabledIfsFeature": [],
        "must_report": False,
        "fixImpact": None,
        "definition": None,
        "threatInfo": None,
        "howtofix": None,
        "cvss": None}


class ARPproxy:
    def __init__(self):
        self.metric_name = 'proxyArp'
        self.long_name = 'ARP proxy'
        self.proxy = {
        "disabledIfsFeature": [],
        "enabledIfsFeature": [],
        "must_report": False,
        "fixImpact": None,
        "definition": None,
        "threatInfo": None,
        "howtofix": None,
        "cvss": None}


class Ntp:
    def __init__(self):
        self.metric_name = 'ntp'
        self.long_name = 'NTP'
        self.authentication = {
        "authenticate": (None),
        "key": (None),
        "must_report": False,
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
        self.metric_name = 'bgp'
        self.long_name = 'BGP'
        self.ttlSecurity = {
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "desc": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.sessionPassword = {
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "desc": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.maxPrefixes = {
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "desc": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.prefixList = {
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "desc": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.aspathList = {
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "desc": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.maxpathlimit = {
        "must_report": False,
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
        self.metric_name = 'eigrp'
        self.long_name = 'EIGRP'
        self.asNumber = []
        self.activeIfaces = []
        self.passive = {
        "cmdInCfg": (None),
        "must_report": False,
        "asn": [],
        "fixImpact": (None),
        "definition": (None),
        "desc": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.auth_md5 = {
        "cmdInCfg": (None),
        "interfaces": [],
        "asn": [],
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "desc": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.rfilter_in = {
        "cmdInCfg": (None),
        "must_report": False,
        "asn": [],
        "fixImpact": (None),
        "definition": (None),
        "desc": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.rfilter_out = {
        "cmdInCfg": (None),
        "must_report": False,
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
        self.metric_name = 'rip'
        self.long_name = 'RIP'
        self.version = None
        self.auth_md5 = {
        "cmdInCfg": (None),
        "must_report": False,
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
        self.metric_name = 'ospf'
        self.long_name = 'OSPF'
        self.area = []
        self.passive = {
        "pid": [],
        "cmdInCfg": (None),
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "desc": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.auth_md5 = {
        "cmdInCfg": (None),
        "must_report": False,
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
        self.rfilter_in = {
        "cmdInCfg": (None),
        "area": [],
        "pid": [],
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "desc": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }
        self.rfilter_out = {
        "cmdInCfg": (None),
        "area": [],
        "pid": [],
        "must_report": False,
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
        "must_report": False,
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
        self.metric_name = 'glbp'
        self.long_name = 'GLBP'
        self.auth_md5 = {
        "cmdInCfg": (None),
        "must_report": False,
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
        self.metric_name = 'hsrp'
        self.long_name = 'HSRP'
        self.auth_md5 = {
        "cmdInCfg": (None),
        "must_report": False,
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
        self.metric_name = 'vrrp'
        self.long_name = 'VRRP'
        self.auth_md5 = {
        "cmdInCfg": (None),
        "must_report": False,
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
        self.metric_name = 'ipoptions'
        self.long_name = 'IPv4 Options'
        self.drop = {
        "cmdInCfg": (None),
        "must_report": False,
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
        self.metric_name = 'ipsourceroute'
        self.long_name = 'IPv4 source route'
        self.drop = {
        "cmdInCfg": (None),
        "must_report": False,
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
        self.metric_name = 'icmpdeny'
        self.long_name = 'ICMP deny any any'
        self.filtered = {
        "cmdInCfg": (None),
        "must_report": False,
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
        self.metric_name = 'ipfrags'
        self.long_name = 'IPv4 fragments'
        self.filtered = {
        "tcp": (None),
        "udp": (None),
        "icmp": (None),
        "ip": (None),
        "must_report": False,
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
        self.metric_name = 'urpf'
        self.long_name = 'Unicast Reverse Path Forwarding (IPv4)'
        self.spoofing = {
        "candidates": [],
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }

class URPFv6:
    def __init__(self):
        self.metric_name = 'urpfv6'
        self.long_name = 'Unicast Reverse Path Forwarding (IPv6)'
        self.spoofing = {
        "candidates": [],
        "must_report": False,
        "fixImpact": (None),
        "definition": (None),
        "threatInfo": (None),
        "howtofix": (None),
        "upgrade": (None),
        "cvss": (None)
        }

class PortSecurity:
    def __init__(self):
        self.metric_name = 'portsecurity'
        self.long_name = 'Port Security'
        self.sticky = {
        "candidates": [],
        "cmdInCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        self.metric_name = 'ipv6'
        self.long_name = 'IPv6'
        self.rh0 = {
        "Notfiltered": [],
        "cmdInCfg": (None),
        "must_report": False,
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
        self.metric_name = 'ipsec'
        self.long_name = 'IPSEC'
        self.cacIKE = {
        "cmdInCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        self.metric_name = 'tclsh'
        self.long_name = 'TCLSH shell scripting'
        self.shell = {
        "cmdInCfg": (None),
        "must_report": False,
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
        self.metric_name = 'tcp'
        self.long_name = 'TCP'
        self.synwait = {
        "cmdInCfg": (None),
        "must_report": False,
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
        self.metric_name = 'l2protos'
        self.long_name = 'Level 2'
        self.nonegotiate = {
        "candidates": [],
        "cmdInCfg": (None),
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        "must_report": False,
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
        self.metric_name = 'Netflow'
        self.long_name = 'Netflow'
        self.V9securityL2 = {
        "fragoffset": (None),
        "icmp": (None),
        "ipid": (None),
        "macaddr": (None),
        "packetlen": (None),
        "ttl": (None),
        "vlid": (None),
        "interfacegress": False,
        "must_report": False,
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
        self.metric_name = 'Multicast'
        self.long_name = 'Multicast'
        self.msdp = {
        "safilterin": (None),
        "safilterout": (None),
        "redistributelist": (None),
        "must_report": False,
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
        self.metric_name = 'Qos'
        self.long_name = 'Qos'
