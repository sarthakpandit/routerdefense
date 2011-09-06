# -*- coding: iso-8859-1 -*-

import __builtin__
from routerdefense.common import *

from xml import *

class genericInfo:
    """Generic configuration information storage: IOS version, hostname, switching method, multicast, ipv6."""
    def __init__(self):
        """Set IOS version, hostname, switching method, multicast and IPv6 variables to None."""
        self.iosVersion = None
        self.hostName = None
        self.switchingMethod = None
        self.multicast = None
        self.ipv6 = None

def addBasicInfo(lines):
    """Fetch the generic information (IOS version, hostname, switching method, multicast and IPv6) from the Cisco IOS configuration file."""
    genericCfg = genericInfo()
    genericCfg.switchingMethod = "Unknown"
    genericCfg.hostName = "Unknown"
    genericCfg.iosVersion = "Unknown"
    try:
        genericCfg.hostName = search_string(lines, 'hostname').split(' ',1)[1]
        genericCfg.iosVersion = search_string(lines, 'version').split(' ',1)[1]
    except:
        raise "No hostname nor version detected in the configuration file."

    if search_string(lines, 'ip cef') is not None:
        genericCfg.switchingMethod = "CEF"
    if search_string(lines, 'no ip route-cache') is not None:
        genericCfg.switchingMethod = "Process switching (CPU)"
    if search_string(lines, 'ip route-cache') is not None:
        genericCfg.switchingMethod = "Fast switching"
    if search_string(lines, 'ip multicast-routing') is not None:
        genericCfg.multicast = "Enabled"
    else:
        genericCfg.multicast = "Disabled"
    if ( (search_string(lines, 'mls qos') is not None) or (search_re_string(lines, '^ip rsvp bandwith .*$') is not None) ):
        genericCfg.qos = "Enabled"
    else:
        genericCfg.qos = "Disabled"
    if search_string(lines, 'ipv6 unicast-routing') is not None:
        genericCfg.ipv6 = "Enabled"
    else:
        genericCfg.ipv6 = "Disabled"
    if search_re_string(lines, '^crypto map \w+$') is not None:
        genericCfg.ipsec = "Enabled"
    else:
        genericCfg.ipsec = "Disabled"

    return genericCfg

def CheckExecTimeout(timeout):
    """Detect if the session timeout is disable or too large."""
    Compliant = True
    if timeout <= 0:
        Compliant = False
    elif timeout >= 180:
        Compliant = False
    return Compliant

def analyzorConsole(consoleCfg,con0,lines):
    """Console port assessment."""
    try:
        con0.execTimeout['cmdInCfg'] = int(search_string(consoleCfg, 'exec-timeout').split(' ',3)[2]) + int(search_string(consoleCfg, 'exec-timeout').split(' ',3)[1]) * 60
    except AttributeError:
        con0.execTimeout['cmdInCfg'] = None

    try:
        con0.privilegezero['cmdInCfg'] = search_string(consoleCfg, 'privilege 0')
        con0.privilegezero['loginlocal'] = search_string(consoleCfg, 'login local')
    except AttributeError:
        con0.privilegezero['cmdInCfg'] = None

    if con0.privilegezero['cmdInCfg'] is None:
        if con0.privilegezero['loginlocal'] is None:
            items = search_xml('consoleprivilegezero')
            cvssMetrics = str(cvss_score(items[5]))
            con0.privilegezero = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "upgrade": (items[4]),
            "cvss": (cvssMetrics)}
        else:
            try:
                con0.privilegezero['globalusername'] = search_re_string(lines, '^username .* privilege 0$')
            except AttributeError:
                pass
            if con0.privilegezero['globalusername'] is None:
                items = search_xml('consoleprivilegezero')
                cvssMetrics = str(cvss_score(items[5]))
                con0.privilegezero = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3]),
                "upgrade": (items[4]),
                "cvss": (cvssMetrics)}
            else:
                con0.privilegezero['must_report'] = False
    else:
        con0.privilegezero['must_report'] = False

    if con0.execTimeout['cmdInCfg'] is not None:
        CheckExecTimeout(con0.execTimeout)
        items = search_xml('consoleExecTimeout')
        if CheckExecTimeout(con0.execTimeout['cmdInCfg']) == False:
            cvssMetrics = str(cvss_score(items[5]))
            con0.execTimeout = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "upgrade": (items[4]),
            "cvss": (cvssMetrics)}
        else:
            con0.execTimeout['must_report'] = False
    else:
        items = search_xml('consoleExecTimeout')
        cvssMetrics = str(cvss_score(items[5]))
        con0.execTimeout = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "upgrade": (items[4]),
        "cvss": (cvssMetrics)}
    try:
        con0.password = search_string(consoleCfg, 'password').split(' ',2)[2]
    except AttributeError:
        con0.password = None

    toBeReturned = ''
    if con0.privilegezero['must_report'] == True:
        toBeReturned = con0.privilegezero['definition'] + '\n' + con0.privilegezero['threatInfo'] + '\n\n' + con0.privilegezero['howtofix'] + '\n'
    if con0.execTimeout['must_report'] == True:
        toBeReturned = toBeReturned + con0.execTimeout['definition'] + '\n' + con0.execTimeout['threatInfo'] + '\n\n' + con0.execTimeout['howtofix'] + '\n'
    return toBeReturned

def analyzorAux(auxCfg,aux0):
    """Auxiliary port assessment."""
    try:
        aux0.execTimeout['cmdInCfg'] = int(search_string(auxCfg, 'exec-timeout').split(' ',3)[2]) + int(search_string(auxCfg, 'exec-timeout').split(' ',3)[1]) * 60
    except AttributeError:
        aux0.execTimeout['cmdInCfg'] = None

    try:
        aux0.transportInput['cmdInCfg'] = search_string(auxCfg, 'transport input none')
    except AttributeError:
        aux0.transportInput['cmdInCfg'] = None

    try:
        aux0.transportOutput['cmdInCfg'] = search_string(auxCfg, 'transport output none')
    except AttributeError:
        aux0.transportOutput['cmdInCfg'] = None

    try:
        aux0.noExec['cmdInCfg'] = search_string(auxCfg, 'no exec')
    except AttributeError:
        aux0.noExec['cmdInCfg'] = None

    items = search_xml('auxExecTimeout')
    if aux0.execTimeout['cmdInCfg'] is not None:
        if CheckExecTimeout(aux0.execTimeout) == False:
            cvssMetrics = str(cvss_score(items[5]))
            aux0.execTimeout = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "upgrade": (items[4]),
            "cvss": (cvssMetrics)}
        else:
            aux0.execTimeout['must_report'] = True
    else:
        cvssMetrics = str(cvss_score(items[5]))
        aux0.execTimeout = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    if aux0.transportInput['cmdInCfg'] is not None:
        aux0.transportInput['must_report'] = False
    else:
        items = search_xml('auxTransportInput')
        cvssMetrics = str(cvss_score(items[5]))
        aux0.transportInput = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}

    if aux0.transportOutput['cmdInCfg'] is not None:
        aux0.transportOutput['must_report'] = False
    else:
        items = search_xml('auxTransportOutput')
        cvssMetrics = str(cvss_score(items[5]))
        aux0.transportOutput = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    if aux0.noExec['cmdInCfg'] is not None:
        aux0.noExec['must_report'] = False
    else:
        items = search_xml('auxNoExec')
        cvssMetrics = str(cvss_score(items[5]))
        aux0.noExec = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        aux0.password = search_string(auxCfg, 'password').split(' ',2)[2]
    except AttributeError:
        aux0.password = None

    toBeReturned = ''
    if aux0.execTimeout['must_report'] == True:
        toBeReturned = aux0.execTimeout['definition'] + '\n' + aux0.execTimeout['threatInfo'] + '\n\n' + aux0.execTimeout['howtofix'] + '\n'
    if aux0.transportInput['must_report'] == True:
        toBeReturned = toBeReturned + aux0.transportInput['definition'] + '\n' + aux0.transportInput['threatInfo'] + '\n\n' + aux0.transportInput['howtofix'] + '\n'
    if aux0.transportOutput['must_report'] == True:
        toBeReturned = toBeReturned + aux0.transportOutput['definition'] + '\n' + aux0.transportOutput['threatInfo'] + '\n\n' + aux0.transportOutput['howtofix'] + '\n'
    if aux0.noExec['must_report'] == True:
        toBeReturned = toBeReturned + aux0.noExec['definition'] + '\n' + aux0.noExec['threatInfo']+ '\n\n' + aux0.noExec['howtofix'] + '\n'

    return toBeReturned

def analyzorVty(vtyCfg,vty):
    """VTY sessions assessment."""
    try:
        vty.execTimeout['cmdInCfg'] = int(search_string(vtyCfg, 'exec-timeout').split(' ',3)[2]) + int(search_string(vtyCfg, 'exec-timeout').split(' ',3)[1]) * 60
    except AttributeError:
        vty.execTimeout['cmdInCfg'] = None

    try:
        vty.transportInput['cmdInCfg'] = search_re_string(vtyCfg, '^transport input (ssh|none)$')
    except AttributeError:
        vty.transportInput['cmdInCfg'] = None

    try:
        vty.transportOutput['cmdInCfg'] = search_re_string(vtyCfg, '^transport output (ssh|none)$')
    except AttributeError:
        vty.transportOutput['cmdInCfg'] = None

    try:
        vty.IPv4accessClass['cmdInCfg'] = search_re_string(vtyCfg, 'access-class .* in$')
    except AttributeError:
        vty.IPv4accessClass['cmdInCfg'] = None

    if __builtin__.genericCfg.ipv6 == "Enabled":
        try:
            vty.IPv6accessClass['cmdInCfg'] = search_re_string(vtyCfg, '^ipv6 access-class .* in$')
        except AttributeError:
            vty.IPv6accessClass['cmdInCfg'] = None

    if vty.execTimeout['cmdInCfg'] is not None:
        items = search_xml('vtyExecTimeout')
        if CheckExecTimeout(vty.execTimeout) == False:
            cvssMetrics = str(cvss_score(items[5]))
            vty.execTimeout = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]).strip().replace('[%vtySessionNumbers]', " ".join(vty.sessionNumbers), 2),
            "upgrade": (items[4]),
            "cvss": (cvssMetrics)}
        else:
            vty.execTimeout['must_report'] = False
    else:
        items = search_xml('vtyExecTimeout')
        cvssMetrics = str(cvss_score(items[5]))
        vty.execTimeout = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]).strip().replace('[%vtySessionNumbers]', " ".join(vty.sessionNumbers), 2),
        "cvss": (cvssMetrics)}

    if vty.transportInput['cmdInCfg'] is not None:
        vty.transportInput['must_report'] = False
    else:
        items = search_xml('vtyTransportInput')
        cvssMetrics = str(cvss_score(items[5]))
        vty.transportInput = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]).strip().replace('[%vtySessionNumbers]', " ".join(vty.sessionNumbers), 2),
        "cvss": (cvssMetrics)}

    if vty.transportOutput['cmdInCfg'] is not None:
        vty.transportOutput['must_report'] = False
    else:
        items = search_xml('vtyTransportOutput')
        cvssMetrics = str(cvss_score(items[5]))
        vty.transportOutput = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]).strip().replace('[%vtySessionNumbers]', " ".join(vty.sessionNumbers), 2),
        "cvss": (cvssMetrics)}

    if vty.IPv4accessClass['cmdInCfg'] is None:
        items = search_xml('vtyIPv4AccessClass')
        cvssMetrics = str(cvss_score(items[5]))
        vty.IPv4accessClass = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]).strip().replace('[%vtySessionNumbers]', " ".join(vty.sessionNumbers), 2),
        "cvss": (cvssMetrics)}
    else:
        accessListNumber = vty.IPv4accessClass['cmdInCfg'].split(' ')[1]
        verifStdACL = False
        verifExtACL = False

        verifStdACL = check_std_acl(vtyCfg, accessListNumber)
        if verifStdACL == False:
            verifExtACL = check_extd_acl(vtyCfg, accessListNumber)

        if verifStdACL == True or verifStdACL == True :
            vty.IPv4accessClass['must_report'] = False
        else:
            try:
                mgmtSubnet = __builtin__.IPv4trustedNetManagementServers[0][0]
            except:
                mgmtSubnet = ""
                pass
            try:
                mgmtWildcardMask = __builtin__.IPv4trustedNetManagementServers[0][3]
            except:
                mgmtWildcardMask = ""
                pass

            items = search_xml('vtyIPv4AccessClass')
            cvssMetrics = str(cvss_score(items[5]))
            vty.IPv4accessClass = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip().replace('[%ManagementSubnet]', mgmtSubnet, 1)),
            "howtofix": (items[3].strip().replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
            "howtofix": (items[3]).strip().replace('[%vtySessionNumbers]', " ".join(vty.sessionNumbers), 2),
            "cvss": (cvssMetrics)}

    if vty.IPv6accessClass['cmdInCfg'] is None:
        vty.IPv6accessClass['must_report'] = False
    else:
        items = search_xml('vtyIPv6AccessClass')
        cvssMetrics = str(cvss_score(items[5]))
        vty.IPv6accessClass = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]).strip().replace('[%vtySessionNumbers]', " ".join(vty.sessionNumbers), 2),
        "cvss": (cvssMetrics)}

    try:
        vty.password = search_string(vtyCfg, 'password').split(' ',2)[2]
    except AttributeError:
        vty.password = None

    toBeReturned = ''
    if vty.execTimeout['must_report'] == True:
        toBeReturned = vty.execTimeout['definition'] + '\n' + vty.execTimeout['threatInfo'] + '\n\n' + vty.execTimeout['howtofix'] + '\n'
    if vty.transportInput['must_report'] == True:
        toBeReturned = toBeReturned + vty.transportInput['definition'] + '\n' + vty.transportInput['threatInfo'] + '\n\n' + vty.transportInput['howtofix'] + '\n'
    if vty.transportOutput['must_report'] == True:
        toBeReturned = toBeReturned + vty.transportOutput['definition'] + '\n' + vty.transportOutput['threatInfo'] + '\n\n' + vty.transportOutput['howtofix'] + '\n'
    if vty.IPv4accessClass['must_report'] == True:
        toBeReturned = toBeReturned + vty.IPv4accessClass['definition'] + '\n' + vty.IPv4accessClass['threatInfo'] + '\n\n' + vty.IPv4accessClass['howtofix'] + '\n'
    if vty.IPv6accessClass['must_report'] == True:
        toBeReturned = toBeReturned + vty.IPv6accessClass['definition'] + '\n' + vty.IPv6accessClass['threatInfo'] + '\n\n' + vty.IPv6accessClass['howtofix'] + '\n'

    return toBeReturned

def analyzorBanner(bannerMotd, motd, bannerType):
    """MOTD, EXEC and LOGIN banner assessment."""
    toBeReturned = ''
    if bannerType == 0:
        if len(bannerMotd) == 0:
            items = search_xml('bannerMOTDconfigured')
            cvssMetrics = str(cvss_score(items[5]))
            motd.configured = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            if search_string(bannerMotd, __builtin__.genericCfg.hostName) is not None :
                items = search_xml('bannerMOTDhostnameIncluded')
                cvssMetrics = str(cvss_score(items[5]))
                motd.routerName = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3]),
                "cvss": (cvssMetrics)}
        if motd.configured['must_report'] == True:
            toBeReturned = motd.configured['definition'] + '\n' + motd.configured['threatInfo'] + '\n\n' + motd.configured['howtofix'] + '\n'
        if motd.routerName['must_report'] == True:
            toBeReturned = toBeReturned + motd.routerName['definition'] + '\n' + motd.routerName['threatInfo'] + '\n\n' + motd.routerName['howtofix'] + '\n'

    if bannerType == 1:
        if len(bannerMotd) == 0:
            items = search_xml('bannerLOGINconfigured')
            cvssMetrics = str(cvss_score(items[5]))
            banLogin.configured = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            if search_string(bannerMotd, __builtin__.genericCfg.hostName) is not None :
                items = search_xml('bannerLOGINhostnameIncluded')
                cvssMetrics = str(cvss_score(items[5]))
                banLogin.routerName = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3]),
                "cvss": (cvssMetrics)}
        if banLogin.configured['must_report'] == True:
            toBeReturned = toBeReturned + banLogin.configured['definition'] + '\n' + banLogin.configured['threatInfo'] + '\n\n' + banLogin.configured['howtofix']
        if banLogin.routerName['must_report'] == True:
            toBeReturned = toBeReturned + banLogin.routerName['definition'] + '\n' + banLogin.routerName['threatInfo']+ '\n\n' + banLogin.routerName['howtofix']

    if bannerType == 2:
        if len(bannerMotd) == 0:
            items = search_xml('bannerEXECconfigured')
            cvssMetrics = str(cvss_score(items[5]))
            banExec.configured = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            if search_string(bannerMotd, __builtin__.genericCfg.hostName) is not None :
                items = search_xml('bannerEXEChostnameIncluded')
                cvssMetrics = str(cvss_score(items[5]))
                banExec.routerName = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3]),
                "cvss": (cvssMetrics)}

        if banExec.configured['must_report'] == True:
            toBeReturned = toBeReturned + banExec.configured['definition'] + '\n' + banExec.configured['threatInfo'] + '\n\n' + banExec.configured['howtofix'] + '\n'
        if banExec.routerName['must_report'] == True:
            toBeReturned = toBeReturned + banExec.routerName['definition'] + '\n' + banExec.routerName['threatInfo'] + '\n\n' + banExec.routerName['howtofix'] + '\n'

    return toBeReturned

def analyzorServices(lines, services):
    """Generic services assessment: password recovery, tcp/udp small servers, finger, bootp, ..."""
    try:
        services.pwdRecovery['cmdInCfg'] = search_string(lines, 'no service password-recovery')
    except AttributeError:
        pass

    if services.pwdRecovery['cmdInCfg'] is not None:
        # feature already configured
        services.pwdRecovery['must_report'] = False
    else:
        items = search_xml('pwdRecovery')
        if __builtin__.iosVersion >= 12.314:
            cvssMetrics = str(cvss_score(items[5]))
            services.pwdRecovery = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.314 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            services.pwdRecovery = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        services.tcpSmallServers['cmdInCfg'] = search_string(lines, 'no service tcp-small-servers')
    except AttributeError:
        pass

    if services.tcpSmallServers['cmdInCfg'] is not None:
        services.tcpSmallServers['must_report'] = False
    else:
        items = search_xml('tcpSmallServers')
        if __builtin__.iosVersion <= 12.0:
            cvssMetrics = str(cvss_score(items[5]))
            services.tcpSmallServers = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            cvssMetrics = str(cvss_score(items[5]))
            services.tcpSmallServers = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        services.udpSmallServers['cmdInCfg'] = search_string(lines, 'no service udp-small-servers')
    except AttributeError:
        pass

    if services.udpSmallServers['cmdInCfg'] is not None:
        services.udpSmallServers['must_report'] = False
    else:
        items = search_xml('udpSmallServers')
        if __builtin__.iosVersion <= 12.0:
            cvssMetrics = str(cvss_score(items[5]))
            services.udpSmallServers = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            cvssMetrics = str(cvss_score(items[5]))
            services.udpSmallServers = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        services.serviceFinger['cmdInCfg'] = search_string(lines, 'no service finger')
    except AttributeError:
        pass

    if services.serviceFinger['cmdInCfg'] is not None:
        services.serviceFinger['must_report'] = False
    else:
        items = search_xml('serviceFinger')
        if __builtin__.iosVersion <= 12.15:
            cvssMetrics = str(cvss_score(items[5]))
            services.serviceFinger = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            cvssMetrics = str(cvss_score(items[5]))
            services.serviceFinger = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        services.serviceBootpServer['cmdInCfg'] = search_string(lines, 'no ip bootp server')
    except AttributeError:
        pass

    if services.serviceBootpServer['cmdInCfg'] is not None:
        services.serviceBootpServer['must_report'] = False
    else:
        items = search_xml('serviceBootpServer')
        cvssMetrics = str(cvss_score(items[5]))
        services.serviceBootpServer = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        services.serviceTcpKeepAliveIn['cmdInCfg'] = search_string(lines, 'service tcp-keepalive-in')
    except AttributeError:
        pass

    if services.serviceTcpKeepAliveIn['cmdInCfg'] is not None:
        services.serviceTcpKeepAliveIn['must_report'] = False
    else:
        items = search_xml('serviceTcpKeepAliveIn')
        cvssMetrics = str(cvss_score(items[5]))
        services.serviceTcpKeepAliveIn = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        services.serviceTcpKeepAliveOut['cmdInCfg'] = search_string(lines, 'service tcp-keepalive-out')
    except AttributeError:
        pass

    if services.serviceTcpKeepAliveOut['cmdInCfg'] is not None:
        services.serviceTcpKeepAliveOut['must_report'] = False
    else:
        items = search_xml('serviceTcpKeepAliveOut')
        cvssMetrics = str(cvss_score(items[5]))
        services.serviceTcpKeepAliveOut = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        services.serviceIpDhcpBootIgnore['cmdInCfg'] = search_string(lines, 'ip dhcp bootp ignore')
    except AttributeError:
        pass

    if services.serviceIpDhcpBootIgnore['cmdInCfg'] is not None:
        services.serviceIpDhcpBootIgnore['must_report'] = False
    else:
        items = search_xml('serviceIpDhcpBootIgnore')
        if __builtin__.iosVersion <= 12.228:
            cvssMetrics = str(cvss_score(items[5]))
            services.serviceIpDhcpBootIgnore = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            cvssMetrics = str(cvss_score(items[5]))
            services.serviceIpDhcpBootIgnore = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        services.serviceDhcp['cmdInCfg'] = search_string(lines, 'no service dhcp')
    except AttributeError:
        pass

    if services.serviceDhcp['cmdInCfg'] is not None:
        services.serviceDhcp['must_report'] = False
    else:
        items = search_xml('serviceDhcp')
        cvssMetrics = str(cvss_score(items[5]))
        services.serviceDhcp = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        services.Mop['cmdInCfg'] = search_string(lines, 'no mop enabled')
    except AttributeError:
        pass

    if services.Mop['cmdInCfg'] is not None:
        services.Mop['must_report'] = False
    else:
        items = search_xml('Mop')
        cvssMetrics = str(cvss_score(items[5]))
        services.Mop = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        services.ipDomainLookup['cmdInCfg'] = search_string(lines, 'no ip domain-lookup')
    except AttributeError:
        pass

    if services.ipDomainLookup['cmdInCfg'] is not None:
        services.ipDomainLookup['must_report'] = False
    else:
        items = search_xml('ipDomainLookup')
        cvssMetrics = str(cvss_score(items[5]))
        services.ipDomainLookup = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        services.servicePad['cmdInCfg'] = search_string(lines, 'no service pad')
    except AttributeError:
        pass

    if services.servicePad['cmdInCfg'] is not None:
        services.servicePad['must_report'] = False
    else:
        items = search_xml('servicePad')
        cvssMetrics = str(cvss_score(items[5]))
        services.servicePad = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        services.serviceHttpServer['cmdInCfg'] = search_string(lines, 'no ip http server')
    except AttributeError:
        pass

    if services.serviceHttpServer['cmdInCfg'] is not None:
        services.serviceHttpServer['must_report'] = False
    else:
        items = search_xml('serviceHttpServer')
        cvssMetrics = str(cvss_score(items[5]))
        services.serviceHttpServer = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        services.serviceHttpsServer['cmdInCfg'] = search_string(lines, 'no ip http secure-server')
    except AttributeError:
        pass

    if services.serviceHttpsServer['cmdInCfg'] is not None:
        services.serviceHttpsServer['must_report'] = False
    else:
        items = search_xml('serviceHttpsServer')
        cvssMetrics = str(cvss_score(items[5]))
        services.serviceHttpsServer = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        services.serviceConfig['cmdInCfg'] = search_string(lines, 'no service config')
    except AttributeError:
        pass

    items = search_xml('serviceConfig')
    if services.serviceConfig['cmdInCfg'] is not None:
        services.serviceConfig['must_report'] = False
    else:
        cvssMetrics = str(cvss_score(items[5]))
        services.serviceConfig = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if services.pwdRecovery['must_report'] == True:
        toBeReturned = services.pwdRecovery['definition'] + '\n' + services.pwdRecovery['threatInfo'] + '\n\n' + services.pwdRecovery['howtofix'] + '\n'
    if services.tcpSmallServers['must_report'] == True:
        toBeReturned = toBeReturned + services.tcpSmallServers['definition'] + '\n' + services.tcpSmallServers['threatInfo'] + '\n\n' + services.tcpSmallServers['howtofix'] + '\n'
    if services.udpSmallServers['must_report'] == True:
        toBeReturned = toBeReturned + services.udpSmallServers['definition'] + '\n' + services.udpSmallServers['threatInfo'] + '\n\n' + services.udpSmallServers['howtofix'] + '\n'
    if services.serviceFinger['must_report'] == True:
        toBeReturned = toBeReturned + services.serviceFinger['definition'] + '\n' + services.serviceFinger['threatInfo'] + '\n\n' + services.serviceFinger['howtofix'] + '\n'
    if services.serviceBootpServer['must_report'] == True:
        toBeReturned = toBeReturned + services.serviceBootpServer['definition'] + '\n' + services.serviceBootpServer['threatInfo'] + '\n\n' + services.serviceBootpServer['howtofix'] + '\n'
    if services.serviceTcpKeepAliveIn['must_report'] == True:
        toBeReturned = toBeReturned + services.serviceTcpKeepAliveIn['definition'] + '\n' + services.serviceTcpKeepAliveIn['threatInfo'] + '\n\n' + services.serviceTcpKeepAliveIn['howtofix'] + '\n'
    if services.serviceTcpKeepAliveOut['must_report'] == True:
        toBeReturned = toBeReturned + services.serviceTcpKeepAliveOut['definition'] + '\n' + services.serviceTcpKeepAliveOut['threatInfo'] + '\n\n' + services.serviceTcpKeepAliveOut['howtofix'] + '\n'
    if services.serviceIpDhcpBootIgnore['must_report'] == True:
        toBeReturned = toBeReturned + services.serviceIpDhcpBootIgnore['definition'] + '\n' + services.serviceIpDhcpBootIgnore['threatInfo'] + '\n\n' + services.serviceIpDhcpBootIgnore['howtofix'] + '\n'
    if services.serviceDhcp['must_report'] == True:
        toBeReturned = toBeReturned + services.serviceDhcp['definition'] + '\n' + services.serviceDhcp['threatInfo'] + '\n\n' + services.serviceDhcp['howtofix'] + '\n'
    if services.Mop['must_report'] == True:
        toBeReturned = toBeReturned + services.Mop['definition'] + '\n' + services.Mop['threatInfo'] + '\n\n' + services.Mop['howtofix'] + '\n'
    if services.ipDomainLookup['must_report'] == True:
        toBeReturned = toBeReturned + services.ipDomainLookup['definition'] + '\n' + services.ipDomainLookup['threatInfo'] + '\n\n' + services.ipDomainLookup['howtofix'] + '\n'
    if services.servicePad['must_report'] == True:
        toBeReturned = toBeReturned + services.servicePad['definition'] + '\n' + services.servicePad['threatInfo'] + '\n\n' + services.servicePad['howtofix'] + '\n'
    if services.serviceHttpServer['must_report'] == True:
        toBeReturned = toBeReturned + services.serviceHttpServer['definition'] + '\n' + services.serviceHttpServer['threatInfo'] + '\n\n' + services.serviceHttpServer['howtofix'] + '\n'
    if services.serviceHttpsServer['must_report'] == True:
        toBeReturned = toBeReturned + services.serviceHttpsServer['definition'] + '\n' + services.serviceHttpsServer['threatInfo'] + '\n\n' + services.serviceHttpsServer['howtofix'] + '\n'
    if services.serviceConfig['must_report'] == True:
        toBeReturned = toBeReturned + services.serviceConfig['definition'] + '\n' + services.serviceConfig['threatInfo'] + '\n\n' + services.serviceConfig['howtofix'] + '\n'

    return toBeReturned

def analyzorMemCpu(lines, memCpu):
    """Memory and CPU configuration assessment."""

    try:
        memCpu.schedulerallocate['cmdInCfg'] = search_string(lines, 'scheduler allocate 4000 400')
    except AttributeError:
        pass

    if memCpu.schedulerallocate['cmdInCfg'] is None:
        memCpu.schedulerallocate['must_report'] = True

    try:
        memCpu.schedulerinterval['cmdInCfg'] = search_string(lines, 'scheduler interval 500')
    except AttributeError:
        pass

    if memCpu.schedulerinterval['cmdInCfg'] is None:
        memCpu.schedulerinterval['must_report'] = True

    if memCpu.schedulerallocate['must_report'] == True:
        items = search_xml('schedulerallocate')
        cvssMetrics = str(cvss_score(items[5]))
        memCpu.schedulerallocate = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    if memCpu.schedulerinterval['must_report'] == True:
        items = search_xml('schedulerinterval')
        cvssMetrics = str(cvss_score(items[5]))
        memCpu.schedulerinterval = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}


    try:
        memCpu.lowWatermarkProcessor['cmdInCfg'] = search_string(lines, 'memory free low-watermark processor')
    except AttributeError:
        pass

    if memCpu.lowWatermarkProcessor['cmdInCfg'] is not None:
        # feature already configured
        memCpu.lowWatermarkProcessor['must_report'] = False
    else:
        items = search_xml('lowWatermarkProcessor')
        if __builtin__.iosVersion >= 12.34:
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.lowWatermarkProcessor = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.34 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.lowWatermarkProcessor = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        memCpu.lowWatermarkIo['cmdInCfg'] = search_string(lines, 'memory free low-watermark io')
    except AttributeError:
        pass
    if memCpu.lowWatermarkIo['cmdInCfg'] is not None:
        # feature already configured
        memCpu.lowWatermarkIo['must_report'] = False
    else:
        items = search_xml('lowWatermarkIo')
        if __builtin__.iosVersion >= 12.34:
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.lowWatermarkIo = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.34 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.lowWatermarkIo = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        memCpu.memReserveCritical['cmdInCfg'] = search_string(lines, 'memory reserve critical')
    except AttributeError:
        pass
    if memCpu.memReserveCritical['cmdInCfg'] is not None:
        # feature already configured
        memCpu.memReserveCritical['must_report'] = False
    else:
        items = search_xml('memReserveCritical')
        if __builtin__.iosVersion >= 12.34:
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.memReserveCritical = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.34 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.memReserveCritical = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        memCpu.memReserveConsole['cmdInCfg'] = search_string(lines, 'memory reserve console')
    except AttributeError:
        pass
    if memCpu.memReserveConsole['cmdInCfg'] is not None:
        # feature already configured
        memCpu.memReserveConsole['must_report'] = False
    else:
        items = search_xml('memReserveConsole')
        if __builtin__.iosVersion >= 12.34:
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.memReserveConsole = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.34 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.memReserveConsole = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}


    try:
        memCpu.memIgnoreOverflowIo['cmdInCfg'] = search_string(lines, 'exception memory ignore overflow io')
    except AttributeError:
        pass
    if memCpu.memIgnoreOverflowIo['cmdInCfg'] is not None:
        # feature already configured
        memCpu.memIgnoreOverflowIo['must_report'] = False
    else:
        items = search_xml('memOverflowIo')
        if __builtin__.iosVersion >= 12.38:
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.memIgnoreOverflowIo = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.38 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.memIgnoreOverflowIo = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        memCpu.memIgnoreOverflowCpu['cmdInCfg'] = search_string(lines, 'exception memory ignore overflow processor')
    except AttributeError:
        pass
    if memCpu.memIgnoreOverflowCpu['cmdInCfg'] is not None:
        # feature already configured
        memCpu.memIgnoreOverflowCpu['must_report'] = False
    else:
        items = search_xml('memOverflowProcessor')
        if __builtin__.iosVersion >= 12.38:
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.memIgnoreOverflowCpu = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.38 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.memIgnoreOverflowCpu = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}


    try:
        memCpu.cpuThresholdNotice['cmdSnmpServerTraps'] = search_string(lines, 'snmp-server enable traps cpu threshold')
    except AttributeError:
        pass
    try:
        memCpu.cpuThresholdNotice['cmdSnmpServerHost'] = search_re_string(lines, 'snmp-server host .* .* cpu')
    except AttributeError:
        pass
    try:
        memCpu.cpuThresholdNotice['cmdCpuThreshold'] = search_re_string(lines, 'process cpu threshold type .* rising .* interval')
    except AttributeError:
        pass
    try:
        memCpu.cpuThresholdNotice['cmdCpuStats'] = search_re_string(lines, 'process cpu statistics limit entry-percentage .*')
    except AttributeError:
        pass

    if ((memCpu.cpuThresholdNotice['cmdSnmpServerTraps'] is not None) and (memCpu.cpuThresholdNotice['cmdSnmpServerHost'] is not None) and (memCpu.cpuThresholdNotice['cmdCpuThreshold'] is not None) and (memCpu.cpuThresholdNotice['cmdCpuStats'] is not None) ):
        memCpu.cpuThresholdNotice['must_report'] = False
    else:
        items = search_xml('cpuThresholdNotification')
        if __builtin__.iosVersion >= 12.34:
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.cpuThresholdNotice = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.34 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.cpuThresholdNotice = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    toBeReturned = ''
    if memCpu.schedulerallocate['must_report'] == True:
        toBeReturned = toBeReturned + memCpu.schedulerallocate['definition'] + '\n' + memCpu.schedulerallocate['threatInfo'] + '\n\n' + memCpu.schedulerallocate['howtofix'] + '\n'
    if memCpu.schedulerinterval['must_report'] == True:
        toBeReturned = toBeReturned + memCpu.schedulerinterval['definition'] + '\n' + memCpu.schedulerinterval['threatInfo'] + '\n\n' + memCpu.schedulerinterval['howtofix'] + '\n'
    if memCpu.lowWatermarkProcessor['must_report'] == True:
        toBeReturned = memCpu.lowWatermarkProcessor['definition'] + '\n' + memCpu.lowWatermarkProcessor['threatInfo'] + '\n\n' + memCpu.lowWatermarkProcessor['howtofix'] + '\n'
    if memCpu.lowWatermarkIo['must_report'] == True:
        toBeReturned = toBeReturned + memCpu.lowWatermarkIo['definition'] + '\n' + memCpu.lowWatermarkIo['threatInfo'] + '\n\n' + memCpu.lowWatermarkIo['howtofix'] + '\n'
    if memCpu.memReserveCritical['must_report'] == True:
        toBeReturned = toBeReturned + memCpu.memReserveCritical['definition'] + '\n' + memCpu.memReserveCritical['threatInfo'] + '\n\n' + memCpu.memReserveCritical['howtofix'] + '\n'
    if memCpu.memReserveConsole['must_report'] == True:
        toBeReturned = toBeReturned + memCpu.memReserveConsole['definition'] + '\n' + memCpu.memReserveConsole['threatInfo'] + '\n\n' + memCpu.memReserveConsole['howtofix'] + '\n'
    if memCpu.memIgnoreOverflowIo['must_report'] == True:
        toBeReturned = toBeReturned + memCpu.memIgnoreOverflowIo['definition'] + '\n' + memCpu.memIgnoreOverflowIo['threatInfo'] + '\n\n' + memCpu.memIgnoreOverflowIo['howtofix'] + '\n'
    if memCpu.memIgnoreOverflowCpu['must_report'] == True:
        toBeReturned = toBeReturned + memCpu.memIgnoreOverflowCpu['definition'] + '\n' + memCpu.memIgnoreOverflowCpu['threatInfo'] + '\n\n' + memCpu.memIgnoreOverflowCpu['howtofix'] + '\n'
    if memCpu.cpuThresholdNotice['must_report'] == True:
        toBeReturned = toBeReturned + memCpu.cpuThresholdNotice['definition'] + '\n' + memCpu.cpuThresholdNotice['threatInfo'] + '\n\n' + memCpu.cpuThresholdNotice['howtofix'] + '\n'

    return toBeReturned

def analyzorCrashinfo(lines, crashinfo):
    """Crashinfo generation configuration assessment."""
    try:
        crashinfo.crashinfoMaxFiles['cmdInCfg'] = search_string(lines, 'exception crashinfo maximum files')
    except AttributeError:
        pass
    if crashinfo.crashinfoMaxFiles['cmdInCfg'] is not None:
        # feature already configured
        crashinfo.crashinfoMaxFiles['must_report'] = False
    else:
        items = search_xml('ExceptionMaximumFiles')
        cvssMetrics = str(cvss_score(items[5]))
        crashinfo.crashinfoMaxFiles = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if crashinfo.crashinfoMaxFiles['must_report'] == True:
        toBeReturned = crashinfo.crashinfoMaxFiles['definition'] + '\n' + crashinfo.crashinfoMaxFiles['threatInfo'] + '\n\n' + crashinfo.crashinfoMaxFiles['howtofix'] + '\n'
    return toBeReturned

def analyzorMPP(lines, vtyList, vtyCfg, mpp):
    """Management plane protection assessment.""" 

    if len(vtyList) == 0:
        # if all vty are removed
        mpp.managementInterface['must_report'] = False
        mpp.sshServer['must_report'] = False
        mpp.scpServer['must_report'] = False
        return

    for i in range(0, len(vtyCfg)):
        for k in range (0, len(vtyCfg[i])):
            if search_string(vtyCfg[i][k], 'transport input none') is not None:
                mpp.managementInterface['must_report'] = False
                mpp.sshServer['must_report'] = False
                mpp.scpServer['must_report'] = False
                return
    if __builtin__.deviceType == 'router':
        try:
            mpp.managementInterface['cpHostCfg'] = search_string(lines, 'control-plane host')
        except AttributeError:
            pass
        try:
            mpp.managementInterface['mgmtIfaceCfg'] = search_re_string(lines, 'management-interface .* allow .*')
        except AttributeError:
            pass

        if mpp.managementInterface['cpHostCfg'] is not None:
            if mpp.managementInterface['mgmtIfaceCfg'] is not None:
                mpp.managementInterface['must_report'] = False
            else:
                if __builtin__.iosVersion >= 12.46:
                    items = search_xml('ManagementPlaneProtection')
                    cvssMetrics = str(cvss_score(items[5]))
                    mpp.managementInterface = {
                    "must_report": True,
                    "fixImpact": (items[0]),
                    "definition": (items[1]),
                    "threatInfo": (items[2]),
                    "howtofix": (items[3]),
                    "cvss": (cvssMetrics)}
                else:
                    items = search_xml('ManagementPlaneProtection')
                    cvssMetrics = str(cvss_score(items[5]))
                    mpp.managementInterface = {
                    "must_report": True,
                    "fixImpact": (items[0]),
                    "definition": (items[1]),
                    "threatInfo": (items[2]),
                    "howtofix": (items[4]),
                    "cvss": (cvssMetrics)}
        else:
            if __builtin__.iosVersion >= 12.46:
                items = search_xml('ManagementPlaneProtection')
                cvssMetrics = str(cvss_score(items[5]))
                mpp.managementInterface = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3]),
                "cvss": (cvssMetrics)}
            else:
                items = search_xml('ManagementPlaneProtection')
                cvssMetrics = str(cvss_score(items[5]))
                mpp.managementInterface = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[4]),
                "cvss": (cvssMetrics)}

    try:
        mpp.sshServerTimeout['timeout'] = search_string(lines, 'ip ssh time-out')
    except AttributeError:
        pass
    try:
        mpp.sshServerAuthRetries['authRetries'] = search_string(lines, 'ip ssh authentication-retries')
    except AttributeError:
        pass
    try:
        mpp.sshServerSourceInterface['sourceInterface'] = search_string(lines, 'ip ssh source-interface')
    except AttributeError:
        pass

    if mpp.sshServerTimeout['timeout'] is None:
        items = search_xml('sshServerTimeout')
        cvssMetrics = str(cvss_score(items[5]))
        mpp.sshServerTimeout = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        mpp.sshServerTimeout['must_report'] = False

    if mpp.sshServerAuthRetries['authRetries'] is None:
        items = search_xml('sshServerAuthretries')
        cvssMetrics = str(cvss_score(items[5]))
        mpp.sshServerAuthRetries = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        mpp.sshServerAuthRetries['must_report'] = False

    if mpp.sshServerSourceInterface['sourceInterface'] is None:
        items = search_xml('sshServerSourceIf')
        cvssMetrics = str(cvss_score(items[5]))
        mpp.sshServerSourceInterface = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        mpp.sshServerSourceInterface['must_report'] = False

    try:
        mpp.scpServer['cmdIncfg'] = search_string(lines, 'ip scp server enable')
    except AttributeError:
        pass

    if mpp.scpServer['cmdIncfg'] is None:
        items = search_xml('sshSCPServer')
        cvssMetrics = str(cvss_score(items[5]))
        mpp.scpServer = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        mpp.scpServer['must_report'] = False

    try:
        mpp.httpSecureServer['cmdIncfg'] = search_string(lines, 'ip http server')
    except AttributeError:
        pass

    if mpp.httpSecureServer['cmdIncfg'] is not None:
        items = search_xml('HTTPServer')
        cvssMetrics = str(cvss_score(items[5]))
        mpp.httpSecureServer = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        mpp.httpSecureServer['must_report'] = False

    try:
        mpp.loginbruteforce['blockfor'] = search_string(lines, 'login block-for')
    except AttributeError:
        pass
    try:
        mpp.loginbruteforce['delay'] = search_string(lines, 'login delay')
    except AttributeError:
        pass
    try:
        mpp.loginbruteforce['quietacl'] = search_string(lines, 'login quiet access-class')
    except AttributeError:
        pass
    try:
        mpp.loginbruteforce['faillog'] = search_string(lines, 'login on-failure log every')
    except AttributeError:
        pass
    try:
        mpp.loginbruteforce['successlog'] = search_string(lines, 'login on-success log every')
    except AttributeError:
        pass
    loginbruteforceCount = 0
    if mpp.loginbruteforce['blockfor'] is not None:
        loginbruteforceCount = loginbruteforceCount + 1
    if mpp.loginbruteforce['delay'] is not None:
        loginbruteforceCount = loginbruteforceCount + 1
    if mpp.loginbruteforce['quietacl'] is not None:
        loginbruteforceCount = loginbruteforceCount + 1
    if mpp.loginbruteforce['faillog'] is not None:
        loginbruteforceCount = loginbruteforceCount + 1
    if mpp.loginbruteforce['successlog'] is not None:
        loginbruteforceCount = loginbruteforceCount + 1

    if loginbruteforceCount < 5:
        if __builtin__.iosVersion >= 12.34:
            items = search_xml('loginBruteforce')
            cvssMetrics = str(cvss_score(items[5]))
            mpp.loginbruteforce = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.3.4 to get the feature
            items = search_xml('loginBruteforce')
            cvssMetrics = str(cvss_score(items[5]))
            mpp.loginbruteforce = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}
    else:
        mpp.loginbruteforce['must_report'] = False

    toBeReturned = ''
    if mpp.managementInterface['must_report'] == True:
        toBeReturned = mpp.managementInterface['definition'] + '\n' + mpp.managementInterface['threatInfo'] + '\n\n' + mpp.managementInterface['howtofix'] + '\n'
    if mpp.sshServerTimeout['must_report'] == True:
        toBeReturned = toBeReturned + mpp.sshServerTimeout['definition'] + '\n' + mpp.sshServerTimeout['threatInfo'] + '\n\n' + mpp.sshServerTimeout['howtofix'] + '\n'
    if mpp.sshServerAuthRetries['must_report'] == True:
        toBeReturned = toBeReturned + mpp.sshServerAuthRetries['definition'] + '\n' + mpp.sshServerAuthRetries['threatInfo'] + '\n\n' + mpp.sshServerAuthRetries['howtofix'] + '\n'
    if mpp.sshServerSourceInterface['must_report'] == True:
        toBeReturned = toBeReturned + mpp.sshServerSourceInterface['definition'] + '\n' + mpp.sshServerSourceInterface['threatInfo'] + '\n\n' + mpp.sshServerSourceInterface['howtofix'] + '\n'
    if mpp.scpServer['must_report'] == True:
        toBeReturned = toBeReturned + mpp.scpServer['definition'] + '\n' + mpp.scpServer['threatInfo'] + '\n\n' + mpp.scpServer['howtofix'] + '\n'
    if mpp.httpSecureServer['must_report'] == True:
        toBeReturned = toBeReturned + mpp.httpSecureServer['definition'] + '\n' + mpp.httpSecureServer['threatInfo'] + '\n\n' + mpp.httpSecureServer['howtofix'] + '\n'
    if mpp.loginbruteforce['must_report'] == True:
        toBeReturned = toBeReturned + mpp.loginbruteforce['definition'] + '\n' + mpp.loginbruteforce['threatInfo'] + '\n\n' + mpp.loginbruteforce['howtofix'] + '\n'

    return toBeReturned

def analyzorPasswordManagement(lines, pwdManagement):
    """Access management assessment."""
    try:
        pwdManagement.enableSecret['cmdInCfg'] = search_string(lines, 'enable secret')
    except AttributeError:
        pass
    if pwdManagement.enableSecret['cmdInCfg'] is not None:
        # feature already configured
        pwdManagement.enableSecret['must_report'] = False
    else:
        items = search_xml('enableSecret')
        cvssMetrics = str(cvss_score(items[5]))
        pwdManagement.enableSecret = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        pwdManagement.svcPwdEncryption['cmdInCfg'] = search_re_string(lines, '^service password-encryption')
    except AttributeError:
        pass
    if pwdManagement.svcPwdEncryption['cmdInCfg'] is not None:
        # feature already configured
        pwdManagement.svcPwdEncryption['must_report'] = False
    else:
        items = search_xml('servicePasswordEncryption')
        cvssMetrics = str(cvss_score(items[5]))
        pwdManagement.svcPwdEncryption = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        pwdManagement.usernameSecret['cmdInCfg'] = search_re_string(lines, '^username .* password .*')
    except AttributeError:
        pass
    if pwdManagement.usernameSecret['cmdInCfg'] is None:
        # feature already configured or not used
        pwdManagement.usernameSecret['must_report'] = False
    else:
        items = search_xml('usernameSecret')
        if __builtin__.iosVersion >= 12.28:
            cvssMetrics = str(cvss_score(items[5]))
            pwdManagement.usernameSecret = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            cvssMetrics = str(cvss_score(items[5]))
            pwdManagement.usernameSecret = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        pwdManagement.retryLockout['aaaNewModel'] = search_re_string(lines, '^aaa new-model')
    except AttributeError:
        pass
    try:
        pwdManagement.retryLockout['usernames'] = search_re_string(lines, '^username .*')
    except AttributeError:
        pass
    try:
        pwdManagement.retryLockout['maxFail'] = search_string(lines, 'aaa local authentication attempts max-fail')
    except AttributeError:
        pass
    try:
        pwdManagement.retryLockout['aaaAuthLoginLocal'] = search_re_string(lines, 'aaa authentication login default (local|.*) ?local')
    except AttributeError:
        pass

    if ((pwdManagement.retryLockout['aaaNewModel'] is not None) and (pwdManagement.retryLockout['maxFail'] is not None) and (pwdManagement.retryLockout['aaaAuthLoginLocal'] is not None) ):
        pwdManagement.retryLockout['must_report'] = False
    elif pwdManagement.retryLockout['usernames'] is None:
        pwdManagement.retryLockout['must_report'] = False
    else:
        items = search_xml('retryLockout')
        if __builtin__.iosVersion >= 12.314:
            cvssMetrics = str(cvss_score(items[5]))
            pwdManagement.retryLockout = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.314 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            pwdManagement.retryLockout = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    toBeReturned = ''
    if pwdManagement.enableSecret['must_report'] == True:
        toBeReturned = pwdManagement.enableSecret['definition'] + '\n' + pwdManagement.enableSecret['threatInfo'] + '\n\n' + pwdManagement.enableSecret['howtofix'] + '\n'
    if pwdManagement.svcPwdEncryption['must_report'] == True:
        toBeReturned = toBeReturned + pwdManagement.svcPwdEncryption['definition'] + '\n' + pwdManagement.svcPwdEncryption['threatInfo'] + '\n\n' + pwdManagement.svcPwdEncryption['howtofix'] + '\n'
    if pwdManagement.usernameSecret['must_report'] == True:
        toBeReturned = toBeReturned + pwdManagement.usernameSecret['definition'] + '\n' + pwdManagement.usernameSecret['threatInfo'] + '\n\n' + pwdManagement.usernameSecret['howtofix'] + '\n'
    if pwdManagement.retryLockout['must_report'] == True:
        toBeReturned = toBeReturned + pwdManagement.retryLockout['definition'] + '\n' + pwdManagement.retryLockout['threatInfo'] + '\n\n' + pwdManagement.retryLockout['howtofix'] + '\n'

    return toBeReturned

def analyzorTacacs(lines, tacacs, mode):
    """Tacacs+ assessment."""
    toBeReturned = ''
    try:
        tacacs.aaaNewModel['cmdInCfg'] = search_string(lines, 'aaa new-model')
    except AttributeError:
        pass

    if mode == 'Authentication':

        try:
            tacacs.authTacacs['cmdInCfg'] = search_re_string(lines, 'aaa authentication login default (group tacacs\+|.*) ?tacacs\+')
        except AttributeError:
            pass

        try:
            tacacs.authFallback['cmdInCfg'] = search_re_string(lines, 'aaa authentication login default (group tacacs\+|.*) (enable|local)')
        except AttributeError:
            pass

        if tacacs.aaaNewModel['cmdInCfg'] is None:
            items = search_xml('aaaNewModel')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.aaaNewmodel = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.aaaNewModel['must_report'] = False

        if tacacs.authTacacs['cmdInCfg'] is None:
            items = search_xml('aaaAuthTacacs')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.authTacacs = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.authTacacs['must_report'] = False

        if tacacs.authFallback['cmdInCfg'] is None:
            items = search_xml('aaaAuthTacacsFallback')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.authFallback = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.authFallback['must_report'] = False

    elif mode == 'Authorization':

        try:
            tacacs.authExec['cmdInCfg'] = search_string(lines, 'aaa authorization exec default group tacacs none')
        except AttributeError:
            pass

        try:
            tacacs.level0['cmdInCfg'] = search_string(lines, 'aaa authorization commands 0 default group tacacs none')
        except AttributeError:
            pass

        try:
            tacacs.level1['cmdInCfg'] = search_string(lines, 'aaa authorization commands 1 default group tacacs none')
        except AttributeError:
            pass

        try:
            tacacs.level15['cmdInCfg'] = search_string(lines, 'aaa authorization commands 15 default group tacacs none')
        except AttributeError:
            pass

        if tacacs.authExec['cmdInCfg'] is None:
            items = search_xml('aaaAuthTacacsExec')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.authExec = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.authExec['must_report'] = False

        if tacacs.level0['cmdInCfg'] is None:
            items = search_xml('aaaAuthTacacsLevel0')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.level0 = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.level0['must_report'] = False

        if tacacs.level1['cmdInCfg'] is None:
            items = search_xml('aaaAuthTacacsLevel1')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.level1 = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.level1['must_report'] = False

        if tacacs.level15['cmdInCfg'] is None:
            items = search_xml('aaaAuthTacacsLevel15')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.level15 = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.level15['must_report'] = False

    elif mode == 'Accounting':

        try:
            tacacs.authAccounting['cmdInCfg'] = search_string(lines, 'aaa accounting exec default start-stop group tacacs')
        except AttributeError:
            pass

        try:
            tacacs.level0['cmdInCfg'] = search_string(lines, 'aaa accounting commands 0 default start-stop group tacacs')
        except AttributeError:
            pass

        try:
            tacacs.level1['cmdInCfg'] = search_string(lines, 'aaa accounting commands 1 default start-stop group tacacs')
        except AttributeError:
            pass

        try:
            tacacs.level15['cmdInCfg'] = search_string(lines, 'aaa accounting commands 15 default start-stop group tacacs')
        except AttributeError:
            pass

        if tacacs.authAccounting['cmdInCfg'] is None:
            items = search_xml('aaaAccountingTacacsExec')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.authAccounting = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.authAccounting['must_report'] = False

        if tacacs.level0['cmdInCfg'] is None:
            items = search_xml('aaaAccountingTacacsLevel0')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.level0 = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.level0['must_report'] = False

        if tacacs.level1['cmdInCfg'] is None:
            items = search_xml('aaaAccountingTacacsLevel1')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.level1 = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.level1['must_report'] = False

        if tacacs.level15['cmdInCfg'] is None:
            items = search_xml('aaaAccountingTacacsLevel15')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.level15 = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.level15['must_report'] = False

    elif mode == 'RedundantAAA':

        countServers = 0
        for line in lines:
            if search_string(lines, 'tacacs-server host') is not None:
                countServers = countServers +1

        if countServers >= 2:
            tacacs.redundant['must_report'] = False
        else:
            items = search_xml('aaaTacacsRedundant')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.redundant = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}

    if mode == 'RedundantAAA':
        if tacacs.redundant['must_report'] == True:
            toBeReturned = tacacs.redundant['definition'] + '\n' + tacacs.redundant['threatInfo'] + '\n\n' + tacacs.redundant['howtofix'] + '\n'
    elif mode == 'Authentication':
        if tacacs.aaaNewModel['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.aaaNewModel['definition'] + '\n' + tacacs.aaaNewModel['threatInfo'] + '\n\n' + tacacs.aaaNewModel['howtofix'] + '\n'
        if tacacs.authTacacs['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.authTacacs['definition'] + '\n' + tacacs.authTacacs['threatInfo'] + '\n\n' + tacacs.authTacacs['howtofix'] + '\n'
        if tacacs.authFallback['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.authFallback['definition'] + '\n' + tacacs.authFallback['threatInfo'] + '\n\n' + tacacs.authFallback['howtofix'] + '\n'
    elif mode == 'Authorization':
        if tacacs.authExec['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.authExec['definition'] + '\n' + tacacs.authExec['threatInfo'] + '\n\n' + tacacs.authExec['howtofix'] + '\n'
        if tacacs.level0['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.level0['definition'] + '\n' + tacacs.level0['threatInfo'] + '\n\n' + tacacs.level0['howtofix'] + '\n'
        if tacacs.level1['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.level1['definition'] + '\n' + tacacs.level1['threatInfo'] + '\n\n' + tacacs.level1['howtofix'] + '\n'
        if tacacs.level15['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.level15['definition'] + '\n' + tacacs.level15['threatInfo'] + '\n\n' + tacacs.level15['howtofix'] + '\n'
    elif mode == 'Accounting':
        if tacacs.authAccounting['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.authAccounting['definition'] + '\n' + tacacs.authAccounting['threatInfo'] + '\n\n' + tacacs.authAccounting['howtofix'] + '\n'
        if tacacs.level0['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.level0['definition'] + '\n' + tacacs.level0['threatInfo'] + '\n\n' + tacacs.level0['howtofix'] + '\n'
        if tacacs.level1['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.level1['definition'] + '\n' + tacacs.level1['threatInfo'] + '\n\n' + tacacs.level1['howtofix'] + '\n'
        if tacacs.level15['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.level15['definition'] + '\n' + tacacs.level15['threatInfo'] + '\n\n' + tacacs.level15['howtofix'] + '\n'

    return toBeReturned

def analyzorSNMP(lines, snmp):
    """SNMP configuration assessment."""
    try:
        snmp.ROcommunity['cmdInCfg'] = search_re_string(lines, 'snmp-server community .* (RO|ro)')
    except AttributeError:
        pass

    try:
        snmp.RWcommunity['cmdInCfg'] = search_re_string(lines, 'snmp-server community .* (RW|rw)')
    except AttributeError:
        pass

    try:
        snmp.ViewROcommunity['cmdInCfg'] = search_re_string(lines, 'snmp-server community .* view .* (RO|ro)')
    except AttributeError:
        pass

    try:
        snmp.ViewRWcommunity['cmdInCfg'] = search_re_string(lines, 'snmp-server community .* view .* (RW|rw)')
    except AttributeError:
        pass

    try:
        snmp.snmpV3['cmdInCfg'] = search_re_string(lines, 'snmp-server group .* v3 (auth|priv)')
    except AttributeError:
        pass

    try:
        mgmtSubnet = __builtin__.IPv4trustedNetManagementServers[0][0]
    except:
        mgmtSubnet = ""
        pass
    try:
        mgmtWildcardMask = __builtin__.IPv4trustedNetManagementServers[0][3]
    except:
        mgmtWildcardMask = ""
        pass

    if snmp.ROcommunity['cmdInCfg'] is None:
        # feature not configured
        snmp.ROcommunity['must_report'] = False
        snmp.ROcommunityACL['must_report'] = False
    else:
        SNMPcommunity = snmp.ROcommunity['cmdInCfg'].split(' ')
        ROsecure = snmp_community_complexity(SNMPcommunity[2])
        if ROsecure == False:
            items = search_xml('snmpROcommunityHardened')
            cvssMetrics = str(cvss_score(items[5]))
            snmp.ROcommunity = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
                .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
            "cvss": (cvssMetrics)}
        try:
            snmp.ROcommunityACL['cmdInCfg'] = search_re_string(lines, 'snmp-server community .* (RO|ro) \d')
        except AttributeError:
            pass

        if snmp.ROcommunityACL['cmdInCfg'] is None:
            items = search_xml('snmpROcommunityHardenedACL')
            cvssMetrics = str(cvss_score(items[5]))
            snmp.ROcommunityACL = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
                .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
            "cvss": (cvssMetrics)}
        else:
            accessListNumber = snmp.ROcommunityACL['cmdInCfg'].split(' ')[4]
            if check_std_acl(lines, accessListNumber) == True:
                snmp.ROcommunityACL['must_report'] = False
            else:
                items = search_xml('snmpROcommunityHardenedACL')
                cvssMetrics = str(cvss_score(items[5]))
                snmp.ROcommunityACL = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3].strip() \
                    .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                    .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
                "cvss": (cvssMetrics)}

    if snmp.RWcommunity['cmdInCfg'] is None:
        # feature not configured
        snmp.RWcommunity['must_report'] = False
        snmp.RWcommunityACL['must_report'] = False
    else:
        SNMPcommunity = snmp.RWcommunity['cmdInCfg'].split(' ')
        RWsecure = snmp_community_complexity(SNMPcommunity[2])
        if RWsecure == False:
            items = search_xml('snmpRWcommunityHardened')
            cvssMetrics = str(cvss_score(items[5]))
            snmp.RWcommunity = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
                .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
            "cvss": (cvssMetrics)}
        try:
            snmp.RWcommunityACL['cmdInCfg'] = search_re_string(lines, 'snmp-server community .* (RW|rw) \d')
        except AttributeError:
            pass

        if snmp.RWcommunityACL['cmdInCfg'] is None:
            items = search_xml('snmpRWcommunityHardenedACL')
            cvssMetrics = str(cvss_score(items[5]))
            snmp.RWcommunityACL = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
                .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
            "cvss": (cvssMetrics)}
        else:
            accessListNumber = snmp.RWcommunityACL['cmdInCfg'].split(' ')[4]
            if check_std_acl(lines, accessListNumber) == True:
                snmp.RWcommunityACL['must_report'] = False
            else:
                items = search_xml('snmpRWcommunityHardenedACL')
                cvssMetrics = str(cvss_score(items[5]))
                snmp.RWcommunityACL = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3].strip() \
                    .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                    .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
                "cvss": (cvssMetrics)}

    if snmp.ViewROcommunity['cmdInCfg'] is None:
        # feature not configured
        snmp.ViewROcommunity['must_report'] = False
        snmp.ViewROcommunityACL['must_report'] = False
    else:
        SNMPcommunity = snmp.ViewROcommunity['cmdInCfg'].split(' ')
        ROsecure = snmp_community_complexity(SNMPcommunity[2])
        if ROsecure == False:
            items = search_xml('ViewsnmpROcommunityHardened')
            cvssMetrics = str(cvss_score(items[5]))
            snmp.ViewROcommunity = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
                .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
            "cvss": (cvssMetrics)}
        try:
            snmp.ViewROcommunityACL['cmdInCfg'] = search_re_string(lines, 'snmp-server community .* view .* (RO|ro) \d')
        except AttributeError:
            pass

        if snmp.ViewROcommunityACL['cmdInCfg'] is None:
            items = search_xml('ViewsnmpROcommunityHardenedACL')
            cvssMetrics = str(cvss_score(items[5]))
            snmp.ViewROcommunityACL = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
                .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
            "cvss": (cvssMetrics)}
        else:
            accessListNumber = snmp.ViewROcommunityACL['cmdInCfg'].split(' ')[4]
            if check_std_acl(lines, accessListNumber) == True:
                snmp.ViewROcommunityACL['must_report'] = False
            else:
                items = search_xml('ViewsnmpROcommunityHardenedACL')
                cvssMetrics = str(cvss_score(items[5]))
                snmp.ViewROcommunityACL = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3].strip() \
                    .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                    .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
                "cvss": (cvssMetrics)}

    if snmp.ViewRWcommunity['cmdInCfg'] is None:
        # feature not configured
        snmp.ViewRWcommunity['must_report'] = False
        snmp.ViewRWcommunityACL['must_report'] = False
    else:
        SNMPcommunity = snmp.ViewRWcommunity['cmdInCfg'].split(' ')
        RWsecure = snmp_community_complexity(SNMPcommunity[2])
        if RWsecure == False:
            items = search_xml('ViewsnmpRWcommunityHardened')
            cvssMetrics = str(cvss_score(items[5]))
            snmp.ViewRWcommunity = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
                .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
            "cvss": (cvssMetrics)}
        try:
            snmp.ViewRWcommunityACL['cmdInCfg'] = search_re_string(lines, 'snmp-server community .* view .* (RW|rw) \d')
        except AttributeError:
            pass

        if snmp.ViewRWcommunityACL['cmdInCfg'] is None:
            items = search_xml('snmpRWcommunityHardenedACL')
            cvssMetrics = str(cvss_score(items[5]))
            snmp.ViewRWcommunityACL = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
            .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
            .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
            "cvss": (cvssMetrics)}
        else:
            accessListNumber = snmp.ViewRWcommunityACL['cmdInCfg'].split(' ')[4]
            if check_std_acl(lines, accessListNumber) == True:
                snmp.ViewRWcommunityACL['must_report'] = False
            else:
                items = search_xml('ViewsnmpRWcommunityHardenedACL')
                cvssMetrics = str(cvss_score(items[5]))
                snmp.ViewRWcommunityACL = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3].strip() \
                    .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                    .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
                "cvss": (cvssMetrics)}

    if snmp.snmpV3['cmdInCfg'] is None:
        # feature not configured
        items = search_xml('snmpVersion3')
        cvssMetrics = str(cvss_score(items[5]))
        snmp.snmpV3 = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3].strip() \
            .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
            .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
        "cvss": (cvssMetrics)}

    else:
        snmp.snmpV3['must_report'] = False

    toBeReturned = ''
    if snmp.ROcommunity['must_report'] == True:
        toBeReturned = snmp.ROcommunity['definition'] + '\n' + snmp.ROcommunity['threatInfo'] + '\n\n' + snmp.ROcommunity['howtofix'] + '\n'
    if snmp.ROcommunityACL['must_report'] == True:
        toBeReturned = toBeReturned + snmp.ROcommunityACL['definition'] + '\n' + snmp.ROcommunityACL['threatInfo'] + '\n\n' + snmp.ROcommunityACL['howtofix'] + '\n'
    if snmp.RWcommunity['must_report'] == True:
        toBeReturned = toBeReturned + snmp.RWcommunity['definition'] + '\n' + snmp.RWcommunity['threatInfo'] + '\n\n' + snmp.RWcommunity['howtofix'] + '\n'
    if snmp.RWcommunityACL['must_report'] == True:
        toBeReturned = toBeReturned + snmp.RWcommunityACL['definition'] + '\n' + snmp.RWcommunityACL['threatInfo'] + '\n\n' + snmp.RWcommunityACL['howtofix'] + '\n'
    if snmp.ViewROcommunity['must_report'] == True:
        toBeReturned = toBeReturned + snmp.ViewROcommunity['definition'] + '\n' + snmp.ViewROcommunity['threatInfo'] + '\n\n' + snmp.ViewROcommunity['howtofix'] + '\n'
    if snmp.ViewROcommunityACL['must_report'] == True:
        toBeReturned = toBeReturned + snmp.ViewROcommunityACL['definition'] + '\n' + snmp.ViewROcommunityACL['threatInfo'] + '\n\n' + snmp.ViewROcommunityACL['howtofix'] + '\n'
    if snmp.ViewRWcommunity['must_report'] == True:
        toBeReturned = toBeReturned + snmp.ViewRWcommunity['definition'] + '\n' + snmp.ViewRWcommunity['threatInfo'] + '\n\n' + snmp.ViewRWcommunity['howtofix'] + '\n'
    if snmp.ViewRWcommunityACL['must_report'] == True:
        toBeReturned = toBeReturned + snmp.ViewRWcommunityACL['definition'] + '\n' + snmp.ViewRWcommunityACL['threatInfo'] + '\n\n' + snmp.ViewRWcommunityACL['howtofix'] + '\n'
    if snmp.snmpV3['must_report'] == True:
        toBeReturned = toBeReturned + snmp.snmpV3['definition'] + '\n' + snmp.snmpV3['threatInfo'] + '\n\n' + snmp.snmpV3['howtofix'] + '\n'

    return toBeReturned

def analyzorSyslog(lines, syslog):
    """Syslog assessment."""
    try:
        syslog.Server['cmdInCfg'] = search_string(lines, 'logging host')
    except AttributeError:
        pass

    if syslog.Server['cmdInCfg'] is None:
        # feature not configured
        try:
            mgmtSubnet = __builtin__.IPv4trustedNetManagementServers[0][0]
        except:
            mgmtSubnet = ""
            pass
        try:
            mgmtWildcardMask = __builtin__.IPv4trustedNetManagementServers[0][3]
        except:
            mgmtWildcardMask = ""
            pass


        items = search_xml('syslogServer')
        cvssMetrics = str(cvss_score(items[5]))

        if len(mgmtSubnet) > 0:
            syslog.Server = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
                .replace('[%ManagementSyslog]', mgmtSubnet, 1)),
            "cvss": (cvssMetrics)}
        else:
            syslog.Server = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
                .replace('[%ManagementSyslog]', 'new-syslog-server', 1)),
            "cvss": (cvssMetrics)}

    else:
        syslog.Server['must_report'] = False

    try:
        syslog.levelTrap['cmdInCfg'] = search_string(lines, 'logging trap')
    except AttributeError:
        pass
    if syslog.levelTrap['cmdInCfg'] is None:
        # feature not configured
        items = search_xml('syslogLevelTrap')
        cvssMetrics = str(cvss_score(items[5]))
        syslog.levelTrap = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        level = syslog.levelTrap['cmdInCfg'].split(' ')[2]
        if level.isdigit() == False:
            if level.strip().lower() == "emergencies":
                level = 0
            elif level.strip().lower() == "alerts":
                level = 1
            elif level.strip().lower() == "critical":
                level = 2
            elif level.strip().lower() == "errors":
                level = 3
            elif level.strip().lower() == "warnings":
                level = 4
            elif level.strip().lower() == "notifications":
                level = 5
            elif level.strip().lower() == "informational":
                level = 6
            elif level.strip().lower() == "debugging":
                level = 7

        if int(level) <= 6:
            syslog.levelTrap['must_report'] = False
        else:
            items = search_xml('syslogLevelTrap')
            cvssMetrics = str(cvss_score(items[5]))
            syslog.levelTrap = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}

    try:
        syslog.levelBuffered['cmdInCfg'] = search_re_string(lines, 'logging buffered \d')
    except AttributeError:
        pass
    if syslog.levelBuffered['cmdInCfg'] is None:
        # feature not configured
        items = search_xml('syslogLevelBuffered')
        cvssMetrics = str(cvss_score(items[5]))
        syslog.levelBuffered = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        level = syslog.levelBuffered['cmdInCfg'].split(' ')[2]
        if int(level) == 6:
            syslog.levelBuffered['must_report'] = False
        else:
            items = search_xml('syslogLevelBuffered')
            cvssMetrics = str(cvss_score(items[5]))
            syslog.levelBuffered = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}

    try:
        syslog.loggingConsole['cmdInCfg'] = search_string(lines, 'no logging console')
    except AttributeError:
        pass
    if syslog.loggingConsole['cmdInCfg'] is None:
        # feature not configured
        items = search_xml('syslogConsole')
        cvssMetrics = str(cvss_score(items[5]))
        syslog.loggingConsole = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        syslog.loggingConsole['must_report'] = False

    try:
        syslog.loggingMonitor['cmdInCfg'] = search_string(lines, 'no logging monitor')
    except AttributeError:
        pass
    if syslog.loggingMonitor['cmdInCfg'] is None:
        # feature not configured
        items = search_xml('syslogMonitor')
        cvssMetrics = str(cvss_score(items[5]))
        syslog.loggingMonitor = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        syslog.loggingMonitor['must_report'] = False

    try:
        syslog.loggingBuffered['cmdInCfg'] = search_re_string(lines, 'logging buffered .* .*')
    except AttributeError:
        pass
    if syslog.loggingBuffered['cmdInCfg'] is None:
        # feature not configured
        items = search_xml('syslogBuffered')
        cvssMetrics = str(cvss_score(items[5]))
        syslog.loggingBuffered = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        size = syslog.loggingBuffered['cmdInCfg'].split(' ')[2]
        level = syslog.loggingBuffered['cmdInCfg'].split(' ')[3]
        if level.isdigit() == False:
            if level.strip().lower() == "emergencies":
                level = 0
            if level.strip().lower() == "alerts":
                level = 1
            if level.strip().lower() == "critical":
                level = 2
            if level.strip().lower() == "errors":
                level = 3
            if level.strip().lower() == "warnings":
                level = 4
            if level.strip().lower() == "notification":
                level = 5
            if level.strip().lower() == "informational":
                level = 6
            if level.strip().lower() == "debugging":
                level = 7
        if ( (int(size) >= 16000) and (int(level) == 6) ):
            syslog.loggingBuffered['must_report'] = False
        else:
            items = search_xml('syslogBuffered')
            cvssMetrics = str(cvss_score(items[5]))
            syslog.loggingBuffered = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}

    try:
        syslog.Interface['cmdInCfg'] = search_string(lines, 'logging source-interface loopback')
    except AttributeError:
        pass
    if syslog.Interface['cmdInCfg'] is None:
        # feature not configured
        items = search_xml('syslogInterface')
        cvssMetrics = str(cvss_score(items[5]))
        syslog.Interface = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        syslog.Interface['must_report'] = False

    try:
        syslog.timestamp['cmdInCfg'] = search_string(lines, 'service timestamps log datetime msec show-timezone')
    except AttributeError:
        pass
    if syslog.timestamp['cmdInCfg'] is None:
        # feature not configured
        items = search_xml('syslogTimestamp')
        cvssMetrics = str(cvss_score(items[5]))
        syslog.timestamp = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        syslog.timestamp['must_report'] = False

    if __builtin__.deviceType == 'router':
        try:
            syslog.serverarp['cmdInCfg'] = search_string(lines, 'logging server-arp')
        except AttributeError:
            pass
        if syslog.serverarp['cmdInCfg'] is None:
            # feature not configured
            if __builtin__.iosVersion >= 12.3:
                items = search_xml('syslogServerArp')
                cvssMetrics = str(cvss_score(items[5]))
                syslog.serverarp = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3]),
                "cvss": (cvssMetrics)}
            else:
                # upgrade to >= 12.3 to get the feature
                items = search_xml('syslogServerArp')
                cvssMetrics = str(cvss_score(items[5]))
                syslog.serverarp = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[4]),
                "cvss": (cvssMetrics)}
        else:
            syslog.serverarp['must_report'] = False

    toBeReturned = ''
    if syslog.Server['must_report'] == True:
        toBeReturned = syslog.Server['definition'] + '\n' + syslog.Server['threatInfo'] + '\n\n' + syslog.Server['howtofix'] + '\n'
    if syslog.levelTrap['must_report'] == True:
        toBeReturned = toBeReturned + syslog.levelTrap['definition'] + '\n' + syslog.levelTrap['threatInfo'] + '\n\n' + syslog.levelTrap['howtofix'] + '\n'
    if syslog.levelBuffered['must_report'] == True:
        toBeReturned = toBeReturned + syslog.levelBuffered['definition'] + '\n' + syslog.levelBuffered['threatInfo'] + '\n\n' + syslog.levelBuffered['howtofix'] + '\n'
    if syslog.loggingConsole['must_report'] == True:
        toBeReturned = toBeReturned + syslog.loggingConsole['definition'] + '\n' + syslog.loggingConsole['threatInfo'] + '\n\n' + syslog.loggingConsole['howtofix'] + '\n'
    if syslog.loggingMonitor['must_report'] == True:
        toBeReturned = toBeReturned + syslog.loggingMonitor['definition'] + '\n' + syslog.loggingMonitor['threatInfo'] + '\n\n' + syslog.loggingMonitor['howtofix'] + '\n'
    if syslog.loggingBuffered['must_report'] == True:
        toBeReturned = toBeReturned + syslog.loggingBuffered['definition'] + '\n' + syslog.loggingBuffered['threatInfo'] + '\n\n' + syslog.loggingBuffered['howtofix'] + '\n'
    if syslog.Interface['must_report'] == True:
        toBeReturned = toBeReturned + syslog.Interface['definition'] + '\n' + syslog.Interface['threatInfo'] + '\n\n' + syslog.Interface['howtofix'] + '\n'
    if syslog.timestamp['must_report'] == True:
        toBeReturned = toBeReturned + syslog.timestamp['definition'] + '\n' + syslog.timestamp['threatInfo'] + '\n\n' + syslog.timestamp['howtofix'] + '\n'
    if syslog.serverarp['must_report'] == True:
        toBeReturned = toBeReturned + syslog.serverarp['definition'] + '\n' + syslog.serverarp['threatInfo'] + '\n\n' + syslog.serverarp['howtofix'] + '\n'

    return toBeReturned


def analyzorArchive(lines, archive):
    """Archive configuration assessment."""
    try:
        archive.configuration['cmdInCfg'] = search_re_string(lines, '^archive$')
    except AttributeError:
        pass
    if archive.configuration['cmdInCfg'] is not None:
        # feature already configured
        if search_re_string(lines, 'time-period') is not None:
            archive.configuration['must_report'] = False
        else:
            items = search_xml('archiveConfiguration')
            if __builtin__.iosVersion >= 12.37:
                cvssMetrics = str(cvss_score(items[5]))
                archive.configuration = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3]),
                "cvss": (cvssMetrics)}
            else:
            # upgrade to >= 12.37 to get the feature
                cvssMetrics = str(cvss_score(items[5]))
                archive.configuration = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[4]),
                "cvss": (cvssMetrics)}

    try:
        archive.exclusive['cmdInCfg'] = search_string(lines, 'configuration mode exclusive auto')
    except AttributeError:
        pass
    if archive.exclusive['cmdInCfg'] is not None:
        # feature already configured
        archive.exclusive['must_report'] = False
    else:
        items = search_xml('archiveExclusive')
        if __builtin__.iosVersion >= 12.314:
            cvssMetrics = str(cvss_score(items[5]))
            archive.exclusive = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.314 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            archive.exclusive = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        archive.secureBoot['cmdInCfg'] = search_string(lines, 'secure boot-image')
    except AttributeError:
        pass
    if archive.secureBoot['cmdInCfg'] is not None:
        # feature already configured
        archive.secureBoot['must_report'] = False
    else:
        items = search_xml('archiveSecureImage')
        if __builtin__.iosVersion >= 12.38:
            cvssMetrics = str(cvss_score(items[5]))
            archive.secureBoot = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.38 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            archive.secureBoot = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        archive.secureConfig['cmdInCfg'] = search_string(lines, 'secure boot-config')
    except AttributeError:
        pass
    if archive.secureConfig['cmdInCfg'] is not None:
        # feature already configured
        archive.secureConfig['must_report'] = False
    else:
        items = search_xml('archiveSecureConfig')
        if __builtin__.iosVersion >= 12.38:
            cvssMetrics = str(cvss_score(items[5]))
            archive.secureConfig = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.38 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            archive.secureConfig = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        archive.logs['cmdInCfg'] = search_re_string(lines, '^archive$')
    except AttributeError:
        pass
    if archive.logs['cmdInCfg'] is not None:
        # feature already configured
        if ( (search_string(lines, 'hidekeys') is not None) and (search_string(lines, 'logging enable') is not None )):
            archive.logs['must_report'] = False
        else:
            items = search_xml('archiveLogs')
            if __builtin__.iosVersion >= 12.34:
                cvssMetrics = str(cvss_score(items[5]))
                archive.logs = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3]),
                "cvss": (cvssMetrics)}
            else:
                # upgrade to >= 12.34 to get the feature
                cvssMetrics = str(cvss_score(items[5]))
                archive.logs = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[4]),
                "cvss": (cvssMetrics)}

    toBeReturned = ''
    if archive.configuration['must_report'] == True:
        toBeReturned = archive.configuration['definition'] + '\n' + archive.configuration['threatInfo'] + '\n\n' + archive.configuration['howtofix'] + '\n'
    if archive.exclusive['must_report'] == True:
        toBeReturned = toBeReturned + archive.exclusive['definition'] + '\n' + archive.exclusive['threatInfo'] + '\n\n' + archive.exclusive['howtofix'] + '\n'
    if archive.secureBoot['must_report'] == True:
        toBeReturned = toBeReturned + archive.secureBoot['definition'] + '\n' + archive.secureBoot['threatInfo'] + '\n\n' + archive.secureBoot['howtofix'] + '\n'
    if archive.secureConfig['must_report'] == True:
        toBeReturned = toBeReturned + archive.secureConfig['definition'] + '\n' + archive.secureConfig['threatInfo'] + '\n\n' + archive.secureConfig['howtofix'] + '\n'
    if archive.logs['must_report'] == True:
        toBeReturned = toBeReturned + archive.logs['definition'] + '\n' + archive.logs['threatInfo'] + '\n\n' + archive.logs['howtofix'] + '\n'

    return toBeReturned

def analyzorICMPRedirects(icmpRedirects, fullConfig, ifaceCfg):
    """ICMP redirects assessments."""
    for i in range(0, len(ifaceCfg)):
        ipIcmpRedirectsFound = False
        for line in ifaceCfg[i].configuration:
            if line == 'ip redirects':
                if not ifaceCfg[i].name.strip() in icmpRedirects.redirects['enabledIfsFeature']:
                    if 'Loopback' in ifaceCfg[i].name.strip():
                        break
                    icmpRedirects.redirects['enabledIfsFeature'].append(ifaceCfg[i].name.strip())
                ipIcmpRedirectsFound = True
            if ipIcmpRedirectsFound == False:
                if not ifaceCfg[i].name.strip() in icmpRedirects.redirects['disabledIfsFeature']:
                    if 'Loopback' in ifaceCfg[i].name.strip():
                        break
                    icmpRedirects.redirects['disabledIfsFeature'].append(ifaceCfg[i].name.strip())
                icmpRedirects.redirects['must_report'] = True

    if icmpRedirects.redirects['must_report'] == True:
        items = search_xml('ipICMPredirects')
        cvssMetrics = str(cvss_score(items[5]))
        icmpRedirects.redirects['fixImpact'] = items[0]
        icmpRedirects.redirects['definition'] = items[1]
        icmpRedirects.redirects['threatInfo'] = items[2]
        icmpRedirects.redirects['howtofix'] = items[3]
        icmpRedirects.redirects['cvss'] = cvssMetrics

        if icmpRedirects.redirects['enabledIfsFeature']:
            icmpRedirects.redirects['howtofix'] = \
                icmpRedirects.redirects['howtofix'].strip() \
                .replace('[%RedirectifsDisabled]', ", " \
                .join(icmpRedirects.redirects['enabledIfsFeature']), 1)
        else:
            icmpRedirects.redirects['howtofix'] = \
                icmpRedirects.redirects['howtofix'].strip() \
                .replace('[%RedirectifsDisabled]', "None", 1)
        if icmpRedirects.redirects['disabledIfsFeature']:
            icmpRedirects.redirects['howtofix'] = \
                icmpRedirects.redirects['howtofix'].strip() \
                .replace('[%RedirectifsEnabled]', ", " \
                .join(icmpRedirects.redirects['disabledIfsFeature']), 1)
        else:
            icmpRedirects.redirects['howtofix'] = \
                icmpRedirects.redirects['howtofix'].strip() \
                .replace('[%RedirectifsEnabled]', "None", 1)

        return icmpRedirects.redirects['definition'] \
             + icmpRedirects.redirects['threatInfo'] \
             + icmpRedirects.redirects['howtofix']

    toBeReturned = ''
    if icmpRedirects.redirects['must_report'] == True:
        toBeReturned = \
            icmpRedirects.redirects['definition'] \
            + '\n' + icmpRedirects.redirects['threatInfo'] \
            + '\n\n' + icmpRedirects.redirects['howtofix'] + '\n'

    return toBeReturned


def analyzorICMPUnreachable(icmpUnreachable, fullConfig, ifaceCfg):
    """ICMP unreachable configuration."""
    for i in range(0, len(ifaceCfg)):
        for line in ifaceCfg[i].configuration:
            ipIcmpUnreachableFound = False
            if line == 'no ip unreachables':
                if ifaceCfg[i].name.strip() not in icmpUnreachable.unreachable['disabledIfsFeature']:
                    if 'Loopback' in ifaceCfg[i].name.strip():
                        break
                    icmpUnreachable.unreachable['disabledIfsFeature'].append(ifaceCfg[i].name.strip())
                ipIcmpUnreachableFound = True
            if ipIcmpUnreachableFound == False:
                if ifaceCfg[i].name.strip() not in icmpUnreachable.unreachable['enabledIfsFeature']:
                    if 'Loopback' in ifaceCfg[i].name.strip():
                        break
                    icmpUnreachable.unreachable['enabledIfsFeature'].append(ifaceCfg[i].name.strip())
                icmpUnreachable.unreachable['must_report'] = True

    try:
        icmpUnreachable.unreachable['unreachableRate'] = search_string(fullConfig, 'ip icmp rate-limit unreachable')
    except AttributeError:
        pass
    if icmpUnreachable.unreachable['unreachableRate'] is None:
        icmpUnreachable.unreachable['must_report'] = True

    if icmpUnreachable.unreachable['must_report'] == True:
        items = search_xml('ipICMPunreachable')
        cvssMetrics = str(cvss_score(items[5]))
        icmpUnreachable.unreachable['fixImpact'] = items[0]
        icmpUnreachable.unreachable['definition'] = items[1]
        icmpUnreachable.unreachable['threatInfo'] = items[2]
        icmpUnreachable.unreachable['howtofix'] = items[3]
        if icmpUnreachable.unreachable['disabledIfsFeature']:
            icmpUnreachable.unreachable['howtofix'] = icmpUnreachable.unreachable['howtofix'].strip().replace('[%UnreachableifsEnabled]', ", ".join(icmpUnreachable.unreachable['disabledIfsFeature']), 1)
        else:
            icmpUnreachable.unreachable['howtofix'] = icmpUnreachable.unreachable['howtofix'].strip().replace('[%UnreachableifsEnabled]', "None", 1)
        if icmpUnreachable.unreachable['enabledIfsFeature']:
            icmpUnreachable.unreachable['howtofix'] = icmpUnreachable.unreachable['howtofix'].strip().replace('[%UnreachableifsDisabled]', ", ".join(icmpUnreachable.unreachable['enabledIfsFeature']), 1)
        else:
            icmpUnreachable.unreachable['howtofix'] = icmpUnreachable.unreachable['howtofix'].strip().replace('[%UnreachableifsDisabled]', "None", 1)


        icmpUnreachable.unreachable['cvss'] = cvssMetrics

    toBeReturned = ''
    if icmpUnreachable.unreachable['must_report'] == True:
        toBeReturned = icmpUnreachable.unreachable['definition'] + '\n' + icmpUnreachable.unreachable['threatInfo'] + '\n\n' + icmpUnreachable.unreachable['howtofix'] + '\n'

    return toBeReturned

def analyzorARPproxy(proxyArp, fullConfig, ifaceCfg):
    """ARP proxy configuration."""
    for i in range(0, len(ifaceCfg)):
        for line in ifaceCfg[i].configuration:
            proxyArpFound = False
            if line == 'no ip proxy-arp':
                if ifaceCfg[i].name.strip() not in proxyArp.proxy['enabledIfsFeature']:
                    if 'Loopback' in ifaceCfg[i].name.strip():
                        break
                    proxyArp.proxy['enabledIfsFeature'].append(ifaceCfg[i].name.strip())
                proxyArpFound = True
            if proxyArpFound == False:
                if ifaceCfg[i].name.strip() not in proxyArp.proxy['disabledIfsFeature']:
                    if 'Loopback' in ifaceCfg[i].name.strip():
                        break
                    proxyArp.proxy['disabledIfsFeature'].append(ifaceCfg[i].name.strip())
                proxyArp.proxy['must_report'] = True

    if proxyArp.proxy['must_report'] == True:
        items = search_xml('proxyArp')
        cvssMetrics = str(cvss_score(items[5]))
        proxyArp.proxy['fixImpact'] = items[0]
        proxyArp.proxy['definition'] = items[1]
        proxyArp.proxy['threatInfo'] = items[2]
        proxyArp.proxy['howtofix'] = items[3]
        if proxyArp.proxy['disabledIfsFeature']:
            proxyArp.proxy['howtofix'] = proxyArp.proxy['howtofix'].strip().replace('[%ArpifsEnabled]', ", ".join(proxyArp.proxy['disabledIfsFeature']), 1)
        else:
            proxyArp.proxy['howtofix'] = proxyArp.proxy['howtofix'].strip().replace('[%ArpifsEnabled]', "None", 1)
        if proxyArp.proxy['enabledIfsFeature']:
            proxyArp.proxy['howtofix'] = proxyArp.proxy['howtofix'].strip().replace('[%ArpifsDisabled]', ", ".join(proxyArp.proxy['enabledIfsFeature']), 1)
        else:
            proxyArp.proxy['howtofix'] = proxyArp.proxy['howtofix'].strip().replace('[%ArpifsDisabled]', "None", 1)

        proxyArp.proxy['cvss'] = cvssMetrics

    toBeReturned = ''
    if proxyArp.proxy['must_report'] == True:
        toBeReturned = proxyArp.proxy['definition'] + '\n' + proxyArp.proxy['threatInfo'] + '\n\n' + proxyArp.proxy['howtofix'] + '\n'

    return toBeReturned

def analyzorNtp(lines, ntp):
    """NTP configuration."""
    try:
        ntp.authentication['authenticate'] = search_string(lines, 'ntp authenticate')
    except AttributeError:
        pass
    try:
        ntp.authentication['key'] = search_string(lines, 'ntp authentication-key')
    except AttributeError:
        pass

    if ( (ntp.authentication['authenticate'] is None) or (ntp.authentication['key'] is None) ):
        ntp.authentication['must_report'] = True

    if ntp.authentication['must_report'] == True:
        items = search_xml('ntpAuthentication')
        cvssMetrics = str(cvss_score(items[5]))
        ntp.authentication = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if ntp.authentication['must_report'] == True:
        toBeReturned = ntp.authentication['definition'] + '\n' + ntp.authentication['threatInfo'] + '\n\n' + ntp.authentication['howtofix'] + '\n'

    return toBeReturned

def analyzorGlbp(lines, glbp, ifaceCfg):
    """GLBP configuration assessment."""

    glbpConfigured = []
    for index in ifaceCfg:
        glbpConfigured = search_re_multi_string(index.configuration,'glbp .* ip .*')
        if len(glbpConfigured) >= 1:
            for indexInstance in glbpConfigured:
                glbpInstance = indexInstance.split(' ')[1]
                authentication = 'glbp ' + glbpInstance + ' authentication md5 key-string .*'
                if search_re_string(index.configuration,authentication) is None:
                    glbp.auth_md5['must_report'] = True

    if glbp.auth_md5['must_report'] == True:
        items = search_xml('glbpMD5')
        cvssMetrics = str(cvss_score(items[5]))
        glbp.auth_md5 = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if glbp.auth_md5['must_report'] == True:
        toBeReturned = glbp.auth_md5['definition'] + '\n' + glbp.auth_md5['threatInfo'] + '\n\n' + glbp.auth_md5['howtofix'] + '\n'

    return toBeReturned


def analyzorHsrp(lines, hsrp, ifaceCfg):
    hsrpConfigured = []
    for index in ifaceCfg:
        hsrpConfigured = search_re_multi_string(index.configuration,'hsrp .* ip .*')
        if len(hsrpConfigured) >= 1:
            for indexInstance in hsrpConfigured:
                hsrpInstance = indexInstance.split(' ')[1]
                authentication = 'hsrp ' + hsrpInstance + ' authentication md5 key-string .*'
                if search_re_string(index.configuration,authentication) is None:
                    hsrp.auth_md5['must_report'] = True

    if hsrp.auth_md5['must_report'] == True:
        items = search_xml('hsrpMD5')
        cvssMetrics = str(cvss_score(items[5]))
        hsrp.auth_md5 = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if hsrp.auth_md5['must_report'] == True:
        toBeReturned = hsrp.auth_md5['definition'] + '\n' + hsrp.auth_md5['threatInfo'] + '\n\n' + hsrp.auth_md5['howtofix'] + '\n'

    return toBeReturned

def analyzorVrrp(lines, vrrp, ifaceCfg):
    """VRRP configuration assessment."""

    vrrpConfigured = []
    for index in ifaceCfg:
        vrrpConfigured = search_re_multi_string(index.configuration,'vrrp .* ip .*')
        if len(vrrpConfigured) >= 1:
            for indexInstance in vrrpConfigured:
                vrrpInstance = indexInstance.split(' ')[1]
                authentication = 'vrrp ' + vrrpInstance + ' authentication md5 key-string .*'
                if search_re_string(index.configuration,authentication) is None:
                    vrrp.auth_md5['must_report'] = True

    if vrrp.auth_md5['must_report'] == True:
        items = search_xml('vrrpMD5')
        cvssMetrics = str(cvss_score(items[5]))
        vrrp.auth_md5 = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if vrrp.auth_md5['must_report'] == True:
        toBeReturned = vrrp.auth_md5['definition'] + '\n' + vrrp.auth_md5['threatInfo'] + '\n\n' + vrrp.auth_md5['howtofix'] + '\n'

    return toBeReturned

def analyzorIPoptions(lines, ipoptions):
    """IP options configuration."""

    try:
        ipoptions.drop['cmdInCfg'] = search_string(lines, 'ip options drop')
    except AttributeError:
        pass
    if ipoptions.drop['cmdInCfg'] is None:
        ipoptions.drop['must_report'] = True

    if ipoptions.drop['must_report'] == True:
        items = search_xml('IPoptions')
        cvssMetrics = str(cvss_score(items[5]))
        ipoptions.drop = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if ipoptions.drop['must_report'] == True:
        toBeReturned = ipoptions.drop['definition'] + '\n' + ipoptions.drop['threatInfo'] + '\n\n' + ipoptions.drop['howtofix'] + '\n'

    return toBeReturned

def analyzorIPsrcRoute(lines, ipsrcroute):
    """IPv4 source-routing configuration."""

    try:
        ipsrcroute.drop['cmdInCfg'] = search_string(lines, 'no ip source-route')
    except AttributeError:
        pass
    if ipsrcroute.drop['cmdInCfg'] is None:
        ipsrcroute.drop['must_report'] = True

    if ipsrcroute.drop['must_report'] == True:
        items = search_xml('IPsourceroute')
        cvssMetrics = str(cvss_score(items[5]))
        ipsrcroute.drop = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if ipsrcroute.drop['must_report'] == True:
        toBeReturned = ipsrcroute.drop['definition'] + '\n' + ipsrcroute.drop['threatInfo'] + '\n\n' + ipsrcroute.drop['howtofix'] + '\n'

    return toBeReturned

def analyzorICMPdeny(lines, denyicmp):
    """ICMP deny configuration."""

    try:
        denyicmp.filtered['cmdInCfg'] = search_string(lines, 'deny icmp any any')
    except AttributeError:
        pass
    if denyicmp.filtered['cmdInCfg'] is None:
        denyicmp.filtered['must_report'] = True

    if denyicmp.filtered['must_report'] == True:
        items = search_xml('ICMPdeny')
        cvssMetrics = str(cvss_score(items[5]))
        denyicmp.filtered = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if denyicmp.filtered['must_report'] == True:
        toBeReturned = denyicmp.filtered['definition'] + '\n' + denyicmp.filtered['threatInfo'] + '\n\n' + denyicmp.filtered['howtofix'] + '\n'

    return toBeReturned

def analyzorIPfragments(lines, ipfrags):
    """IPv4 fragments configuration."""

    try:
        ipfrags.filtered['tcp'] = search_string(lines, 'deny tcp any any fragments')
    except AttributeError:
        pass
    try:
        ipfrags.filtered['udp'] = search_string(lines, 'deny udp any any fragments')
    except AttributeError:
        pass
    try:
        ipfrags.filtered['icmp'] = search_string(lines, 'deny icmp any any fragments')
    except AttributeError:
        pass
    try:
        ipfrags.filtered['ip'] = search_string(lines, 'deny ip any any fragments')
    except AttributeError:
        pass

    if ipfrags.filtered['tcp'] is None:
        ipfrags.filtered['must_report'] = True
    if ipfrags.filtered['udp'] is None:
        ipfrags.filtered['must_report'] = True
    if ipfrags.filtered['icmp'] is None:
        ipfrags.filtered['must_report'] = True
    if ipfrags.filtered['ip'] is None:
        ipfrags.filtered['must_report'] = True

    if ipfrags.filtered['must_report'] == True:
        items = search_xml('IPfrags')
        cvssMetrics = str(cvss_score(items[5]))
        ipfrags.filtered = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if ipfrags.filtered['must_report'] == True:
        toBeReturned = ipfrags.filtered['definition'] + '\n' + ipfrags.filtered['threatInfo'] + '\n\n' + ipfrags.filtered['howtofix'] + '\n'

    return toBeReturned

def analyzorURPF(lines, urpf, ifaceCfg):
    """URPF IPv4 configuration."""
    for i in range(0, len(ifaceCfg)):
        routedPort = 0
        urpfOK = 0
        for line in ifaceCfg[i].configuration:
            if line.startswith('ip address'):
                routedPort = 1
            if routedPort == 1:
                if line.startswith('ip verify unicast source reachable-via'):
                    urpfOK = 1
        if urpfOK == 0 and routedPort == 1 and 'Loopback' not in ifaceCfg[i].name.strip():
            if not ifaceCfg[i].name.strip() in urpf.spoofing['candidates']:
                urpf.spoofing['candidates'].append(ifaceCfg[i].name.strip())
            urpf.spoofing['must_report'] = True

    if urpf.spoofing['must_report'] == True:
        items = search_xml('urpf')
        cvssMetrics = str(cvss_score(items[5]))
        urpf.spoofing['must_report'] = True
        urpf.spoofing['fixImpact'] = items[0]
        urpf.spoofing['definition'] = items[1]
        urpf.spoofing['threatInfo'] = items[2]
        urpf.spoofing['howtofix'] = items[3]
        urpf.spoofing['cvss'] = cvssMetrics

        if urpf.spoofing['candidates']:
            urpf.spoofing['howtofix'] = urpf.spoofing['howtofix'].strip().replace('[%URPFCandidates]', ", ".join(urpf.spoofing['candidates']), 1)

        return urpf.spoofing['definition'] + '\n' + urpf.spoofing['threatInfo'] + '\n\n' + urpf.spoofing['howtofix'] + '\n'
    else:
        return "URPF configuration is OK."

def analyzorURPFv6(lines, urpfv6, ifaceCfg):
    "URPF IPv6 configuration."""
    for j in range(0, len(ifaceCfg)):
        ipv6enable = False
        if search_re_string(ifaceCfg[j].configuration, '^ipv6 enable$') is not None:
            ipv6enable = True
        if ipv6enable == True:
            urpfreachable = False
            if search_re_string(ifaceCfg[j].configuration, '^ipv6 verify unicast source reachable-via (rx|any)$') is None:
                urpfreachable = True
            if search_re_string(ifaceCfg[j].configuration, '^ipv6 verify unicast reverse-path$') is None and urpfreachable == True:
                urpfv6.spoofing['candidates'].append(ifaceCfg[j].name.strip())
                urpfv6.spoofing['must_report'] = True

    if urpfv6.spoofing['must_report'] == True:
        items = search_xml('urpfv6')
        cvssMetrics = str(cvss_score(items[5]))
        urpfv6.spoofing['must_report'] = True
        urpfv6.spoofing['fixImpact'] = items[0]
        urpfv6.spoofing['definition'] = items[1]
        urpfv6.spoofing['threatInfo'] = items[2]
        urpfv6.spoofing['howtofix'] = items[3]
        urpfv6.spoofing['cvss'] = cvssMetrics
        if urpfv6.spoofing['candidates']:
            urpfv6.spoofing['howtofix'] = urpfv6.spoofing['howtofix'].strip().replace('[%URPFv6Candidates]', ", ".join(urpfv6.spoofing['candidates']), 1)

        return urpfv6.spoofing['definition'] + '\n' + urpfv6.spoofing['threatInfo'] + '\n\n' + urpfv6.spoofing['howtofix'] + '\n'
    else:
        return "URPFv6 configuration is OK."

def analyzorIPv6(lines, ipv6, aclIPv6, ifaceCfg):
    """IPv6 configuration assessment: RH0, traffic filter."""
    denyRH0 = (None)
    ACLv6name = (None)
    for i in range(0, len(aclIPv6)):
        denyRH0 = search_re_string(aclIPv6[i].configuration, '^deny ipv6 .* routing-type 0$')
        if denyRH0 is not None:
            ACLv6name = aclIPv6[i].name
            for j in range(0, len(ifaceCfg)):
                ipv6enable = False
                if search_re_string(ifaceCfg[j].configuration, '^ipv6 enable$') is not None:
                    ipv6enable = True
                if search_re_string(ifaceCfg[j].configuration, '^ipv6 traffic-filter '+ ACLv6name.strip() +' in$') is None and ipv6enable == True:
                    ipv6.rh0['Notfiltered'].append(ifaceCfg[j].name.strip())


    try:
        ipv6.rh0['cmdInCfg'] = search_string(lines, 'no ipv6 source-route')
    except AttributeError:
        pass

    if ipv6.rh0['cmdInCfg'] is None:
        if len(ipv6.rh0['Notfiltered']) >= 1:
            ipv6.rh0['must_report'] = True

    if ipv6.rh0['must_report'] == True:
        items = search_xml('IPv6rh0')
        cvssMetrics = str(cvss_score(items[5]))
        ipv6.rh0 = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if ipv6.rh0['must_report'] == True:
        toBeReturned = ipv6.rh0['definition'] + '\n' + ipv6.rh0['threatInfo'] + '\n\n' + ipv6.rh0['howtofix'] + '\n'

    return toBeReturned

def analyzorIPSEC(lines, ipsec):
    """IPSec configuration assessment: call admission."""

    try:
        ipsec.cacIKE['cmdInCfg'] = search_re_string(lines, '^crypto call admission limit ike sa .*$')
    except AttributeError:
        pass
    try:
        ipsec.cacRSC['cmdInCfg'] = search_re_string(lines, '^call admission limit .*$')
    except AttributeError:
        pass

    if ipsec.cacIKE['cmdInCfg'] is None:
            ipsec.cacIKE['must_report'] = True

    if ipsec.cacRSC['cmdInCfg'] is None:
        ipsec.cacRSC['must_report'] = True

    if ipsec.cacIKE['must_report'] == True:
        items = search_xml('IPSECcacIKE')
        cvssMetrics = str(cvss_score(items[5]))
        ipsec.cacIKE = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    if ipsec.cacRSC['must_report'] == True:
        items = search_xml('IPSECcacRSC')
        cvssMetrics = str(cvss_score(items[5]))
        ipsec.cacRSC = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if ipsec.cacIKE['must_report'] == True:
        toBeReturned = ipsec.cacIKE['definition'] + '\n' + ipsec.cacIKE['threatInfo'] + '\n\n' + ipsec.cacIKE['howtofix'] + '\n'
    if ipsec.cacRSC['must_report'] == True:
        toBeReturned = toBeReturned + ipsec.cacRSC['definition'] + '\n' + ipsec.cacRSC['threatInfo'] + '\n\n' + ipsec.cacRSC['howtofix'] + '\n'

    return toBeReturned

def analyzorTclSH(lines, tclsh):
    """TCLShell configuration assessment."""

    try:
        tclsh.shell['cmdInCfg'] = search_re_string(lines, '^event cli pattern \"tclsh\" .*$')
    except AttributeError:
        pass
    if tclsh.shell['cmdInCfg'] is None:
        tclsh.shell['must_report'] = True

    if tclsh.shell['must_report'] == True:
        items = search_xml('tclsh')
        cvssMetrics = str(cvss_score(items[5]))
        tclsh.shell = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if tclsh.shell['must_report'] == True:
        toBeReturned = tclsh.shell['definition'] + '\n' + tclsh.shell['threatInfo'] + '\n\n' + tclsh.shell['howtofix'] + '\n'

    return toBeReturned


def analyzorTcp(lines, tcp):
    """TCP synwait configuration."""

    try:
        tcp.synwait['cmdInCfg'] = search_re_string(lines, '^ip tcp synwait-time .*$')
    except AttributeError:
        pass
    if tcp.synwait['cmdInCfg'] is None:
        tcp.synwait['must_report'] = True
    else:
        timer = tcp.synwait.split(' ')[3]
        if int(timer) <= 15:
            tcp.synwait['must_report'] = False
        else:
            tcp.synwait['must_report'] = True

    if tcp.synwait['must_report'] == True:
        items = search_xml('tcpsynwait')
        cvssMetrics = str(cvss_score(items[5]))
        tcp.synwait = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if tcp.synwait['must_report'] == True:
        toBeReturned = tcp.synwait['definition'] + '\n' + tcp.synwait['threatInfo'] + '\n\n' + tcp.synwait['howtofix'] + '\n'

    return toBeReturned

def analyzorNetflow(lines, netflow, ifaceCfg):
    """Netflow configuration assessment."""

    for j in range(0, len(ifaceCfg)):
        if search_re_string(ifaceCfg[j].configuration, '^ip flow (ingress|egress)$') is not None:
            netflow.V9securityL2['interfacegress'] = True

    if netflow.V9securityL2['interfacegress'] == True:
        try:
            netflow.V9securityL2['fragoffset'] = search_re_string(lines, '^ip flow-capture fragment-offset$')
        except AttributeError:
            pass
        try:
            netflow.V9securityL2['icmp'] = search_re_string(lines, '^ip flow-capture icmp$')
        except AttributeError:
            pass
        try:
            netflow.V9securityL2['ipid'] = search_re_string(lines, '^ip flow-capture ip-id$')
        except AttributeError:
            pass
        try:
            netflow.V9securityL2['macaddr'] = search_re_string(lines, '^ip flow-capture mac-addresses$')
        except AttributeError:
            pass
        try:
            netflow.V9securityL2['packetlen'] = search_re_string(lines, '^ip flow-capture packet-length$')
        except AttributeError:
            pass
        try:
            netflow.V9securityL2['ttl'] = search_re_string(lines, '^ip flow-capture ttl$')
        except AttributeError:
            pass
        try:
            netflow.V9securityL2['vlid'] = search_re_string(lines, '^ip flow-capture vlan-id$')
        except AttributeError:
            pass

    if ( (netflow.V9securityL2['fragoffset'] is None) or (netflow.V9securityL2['icmp'] is None) or (netflow.V9securityL2['ipid'] is None) or (netflow.V9securityL2['macaddr'] is None) or (netflow.V9securityL2['packetlen'] is None) or (netflow.V9securityL2['ttl'] is None) or (netflow.V9securityL2['vlid'] is None) ):
        netflow.V9securityL2['must_report'] = True

    if netflow.V9securityL2['must_report'] == True:
        items = search_xml('netflowV9')
        if __builtin__.iosVersion >= 12.42:
            cvssMetrics = str(cvss_score(items[5]))
            netflow.V9securityL2 = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.42 to get the feature (including L3 fragment-offset)
            cvssMetrics = str(cvss_score(items[5]))
            netflow.V9securityL2 = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    toBeReturned = ''
    if netflow.V9securityL2['must_report'] == True:
        toBeReturned = netflow.V9securityL2['definition'] + '\n' + netflow.V9securityL2['threatInfo'] + '\n\n' + netflow.V9securityL2['howtofix'] + '\n'

    return toBeReturned

def analyzorQos(lines, qos, ifaceCfg):
    """QoS configuration assessment. Not ready."""
    toBeReturned = ''
    return toBeReturned
