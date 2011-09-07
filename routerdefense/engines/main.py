# -*- coding: iso-8859-1 -*-

__docformat__ = 'restructuredtext'
__version__ = '$Id$'

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
    except AttributeError:
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

def Checkexec_timeout(timeout):
    """Detect if the session timeout is disable or too large."""
    Compliant = True
    if timeout <= 0:
        Compliant = False
    elif timeout >= 180:
        Compliant = False
    return Compliant

def engine_console(consoleCfg,con0,lines):
    """Console port assessment."""
    try:
        con0.exec_timeout['cmdInCfg'] = int(search_string(consoleCfg, 'exec-timeout').split(' ',3)[2]) + int(search_string(consoleCfg, 'exec-timeout').split(' ',3)[1]) * 60
    except AttributeError:
        con0.exec_timeout['cmdInCfg'] = None

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

    if con0.exec_timeout['cmdInCfg'] is not None:
        Checkexec_timeout(con0.exec_timeout)
        items = search_xml('consoleexec_timeout')
        if Checkexec_timeout(con0.exec_timeout['cmdInCfg']) == False:
            cvssMetrics = str(cvss_score(items[5]))
            con0.exec_timeout = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "upgrade": (items[4]),
            "cvss": (cvssMetrics)}
        else:
            con0.exec_timeout['must_report'] = False
    else:
        items = search_xml('consoleexec_timeout')
        cvssMetrics = str(cvss_score(items[5]))
        con0.exec_timeout = {
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
    if con0.exec_timeout['must_report'] == True:
        toBeReturned = toBeReturned + con0.exec_timeout['definition'] + '\n' + con0.exec_timeout['threatInfo'] + '\n\n' + con0.exec_timeout['howtofix'] + '\n'
    return toBeReturned

def engine_aux(auxCfg,aux0):
    """Auxiliary port assessment."""
    try:
        aux0.exec_timeout['cmdInCfg'] = int(search_string(auxCfg, 'exec-timeout').split(' ',3)[2]) + int(search_string(auxCfg, 'exec-timeout').split(' ',3)[1]) * 60
    except AttributeError:
        aux0.exec_timeout['cmdInCfg'] = None

    try:
        aux0.transport_input['cmdInCfg'] = search_string(auxCfg, 'transport input none')
    except AttributeError:
        aux0.transport_input['cmdInCfg'] = None

    try:
        aux0.transport_output['cmdInCfg'] = search_string(auxCfg, 'transport output none')
    except AttributeError:
        aux0.transport_output['cmdInCfg'] = None

    try:
        aux0.noExec['cmdInCfg'] = search_string(auxCfg, 'no exec')
    except AttributeError:
        aux0.noExec['cmdInCfg'] = None

    items = search_xml('auxexec_timeout')
    if aux0.exec_timeout['cmdInCfg'] is not None:
        if Checkexec_timeout(aux0.exec_timeout) == False:
            cvssMetrics = str(cvss_score(items[5]))
            aux0.exec_timeout = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "upgrade": (items[4]),
            "cvss": (cvssMetrics)}
        else:
            aux0.exec_timeout['must_report'] = True
    else:
        cvssMetrics = str(cvss_score(items[5]))
        aux0.exec_timeout = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    if aux0.transport_input['cmdInCfg'] is not None:
        aux0.transport_input['must_report'] = False
    else:
        items = search_xml('auxtransport_input')
        cvssMetrics = str(cvss_score(items[5]))
        aux0.transport_input = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}

    if aux0.transport_output['cmdInCfg'] is not None:
        aux0.transport_output['must_report'] = False
    else:
        items = search_xml('auxtransport_output')
        cvssMetrics = str(cvss_score(items[5]))
        aux0.transport_output = {
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
    if aux0.exec_timeout['must_report'] == True:
        toBeReturned = aux0.exec_timeout['definition'] + '\n' + aux0.exec_timeout['threatInfo'] + '\n\n' + aux0.exec_timeout['howtofix'] + '\n'
    if aux0.transport_input['must_report'] == True:
        toBeReturned = toBeReturned + aux0.transport_input['definition'] + '\n' + aux0.transport_input['threatInfo'] + '\n\n' + aux0.transport_input['howtofix'] + '\n'
    if aux0.transport_output['must_report'] == True:
        toBeReturned = toBeReturned + aux0.transport_output['definition'] + '\n' + aux0.transport_output['threatInfo'] + '\n\n' + aux0.transport_output['howtofix'] + '\n'
    if aux0.noExec['must_report'] == True:
        toBeReturned = toBeReturned + aux0.noExec['definition'] + '\n' + aux0.noExec['threatInfo']+ '\n\n' + aux0.noExec['howtofix'] + '\n'

    return toBeReturned

def engine_vty(vtyCfg,vty):
    """VTY sessions assessment."""
    try:
        vty.exec_timeout['cmdInCfg'] = int(search_string(vtyCfg, 'exec-timeout').split(' ',3)[2]) + int(search_string(vtyCfg, 'exec-timeout').split(' ',3)[1]) * 60
    except AttributeError:
        vty.exec_timeout['cmdInCfg'] = None

    try:
        vty.transport_input['cmdInCfg'] = search_re_string(vtyCfg, '^transport input (ssh|none)$')
    except AttributeError:
        vty.transport_input['cmdInCfg'] = None

    try:
        vty.transport_output['cmdInCfg'] = search_re_string(vtyCfg, '^transport output (ssh|none)$')
    except AttributeError:
        vty.transport_output['cmdInCfg'] = None

    try:
        vty.ipv4_access_class['cmdInCfg'] = search_re_string(vtyCfg, 'access-class .* in$')
    except AttributeError:
        vty.ipv4_access_class['cmdInCfg'] = None

    if __builtin__.genericCfg.ipv6 == "Enabled":
        try:
            vty.ipv6_access_class['cmdInCfg'] = search_re_string(vtyCfg, '^ipv6 access-class .* in$')
        except AttributeError:
            vty.ipv6_access_class['cmdInCfg'] = None

    if vty.exec_timeout['cmdInCfg'] is not None:
        items = search_xml('vtyexec_timeout')
        if Checkexec_timeout(vty.exec_timeout) == False:
            cvssMetrics = str(cvss_score(items[5]))
            vty.exec_timeout = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]).strip().replace('[%vtySessionNumbers]', " ".join(vty.sessionNumbers), 2),
            "upgrade": (items[4]),
            "cvss": (cvssMetrics)}
        else:
            vty.exec_timeout['must_report'] = False
    else:
        items = search_xml('vtyexec_timeout')
        cvssMetrics = str(cvss_score(items[5]))
        vty.exec_timeout = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]).strip().replace('[%vtySessionNumbers]', " ".join(vty.sessionNumbers), 2),
        "cvss": (cvssMetrics)}

    if vty.transport_input['cmdInCfg'] is not None:
        vty.transport_input['must_report'] = False
    else:
        items = search_xml('vtytransport_input')
        cvssMetrics = str(cvss_score(items[5]))
        vty.transport_input = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]).strip().replace('[%vtySessionNumbers]', " ".join(vty.sessionNumbers), 2),
        "cvss": (cvssMetrics)}

    if vty.transport_output['cmdInCfg'] is not None:
        vty.transport_output['must_report'] = False
    else:
        items = search_xml('vtytransport_output')
        cvssMetrics = str(cvss_score(items[5]))
        vty.transport_output = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]).strip().replace('[%vtySessionNumbers]', " ".join(vty.sessionNumbers), 2),
        "cvss": (cvssMetrics)}

    if vty.ipv4_access_class['cmdInCfg'] is None:
        items = search_xml('vtyipv4_access_class')
        cvssMetrics = str(cvss_score(items[5]))
        vty.ipv4_access_class = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]).strip().replace('[%vtySessionNumbers]', " ".join(vty.sessionNumbers), 2),
        "cvss": (cvssMetrics)}
    else:
        accessListNumber = vty.ipv4_access_class['cmdInCfg'].split(' ')[1]
        verifStdACL = False
        verifExtACL = False

        verifStdACL = check_std_acl(vtyCfg, accessListNumber)
        if verifStdACL == False:
            verifExtACL = check_extd_acl(vtyCfg, accessListNumber)

        if verifStdACL == True or verifStdACL == True :
            vty.ipv4_access_class['must_report'] = False
        else:
            try:
                mgmtSubnet = __builtin__.ipv4_mgmt_outbound[0][0]
            except TypeError:
                mgmtSubnet = ""
                pass
            try:
                mgmtWildcardMask = __builtin__.ipv4_mgmt_outbound[0][3]
            except TypeError:
                mgmtWildcardMask = ""
                pass

            items = search_xml('vtyipv4_access_class')
            cvssMetrics = str(cvss_score(items[5]))
            vty.ipv4_access_class = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip().replace('[%ManagementSubnet]', mgmtSubnet, 1)),
            "howtofix": (items[3].strip().replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
            "howtofix": (items[3]).strip().replace('[%vtySessionNumbers]', " ".join(vty.sessionNumbers), 2),
            "cvss": (cvssMetrics)}

    if vty.ipv6_access_class['cmdInCfg'] is None:
        vty.ipv6_access_class['must_report'] = False
    else:
        items = search_xml('vtyipv6_access_class')
        cvssMetrics = str(cvss_score(items[5]))
        vty.ipv6_access_class = {
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
    if vty.exec_timeout['must_report'] == True:
        toBeReturned = vty.exec_timeout['definition'] + '\n' + vty.exec_timeout['threatInfo'] + '\n\n' + vty.exec_timeout['howtofix'] + '\n'
    if vty.transport_input['must_report'] == True:
        toBeReturned = toBeReturned + vty.transport_input['definition'] + '\n' + vty.transport_input['threatInfo'] + '\n\n' + vty.transport_input['howtofix'] + '\n'
    if vty.transport_output['must_report'] == True:
        toBeReturned = toBeReturned + vty.transport_output['definition'] + '\n' + vty.transport_output['threatInfo'] + '\n\n' + vty.transport_output['howtofix'] + '\n'
    if vty.ipv4_access_class['must_report'] == True:
        toBeReturned = toBeReturned + vty.ipv4_access_class['definition'] + '\n' + vty.ipv4_access_class['threatInfo'] + '\n\n' + vty.ipv4_access_class['howtofix'] + '\n'
    if vty.ipv6_access_class['must_report'] == True:
        toBeReturned = toBeReturned + vty.ipv6_access_class['definition'] + '\n' + vty.ipv6_access_class['threatInfo'] + '\n\n' + vty.ipv6_access_class['howtofix'] + '\n'

    return toBeReturned

def engine_banner(bannerMotd, motd, bannerType):
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
                motd.device_hostname = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3]),
                "cvss": (cvssMetrics)}
        if motd.configured['must_report'] == True:
            toBeReturned = motd.configured['definition'] + '\n' + motd.configured['threatInfo'] + '\n\n' + motd.configured['howtofix'] + '\n'
        if motd.device_hostname['must_report'] == True:
            toBeReturned = toBeReturned + motd.device_hostname['definition'] + '\n' + motd.device_hostname['threatInfo'] + '\n\n' + motd.device_hostname['howtofix'] + '\n'

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
                banLogin.device_hostname = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3]),
                "cvss": (cvssMetrics)}
        if banLogin.configured['must_report'] == True:
            toBeReturned = toBeReturned + banLogin.configured['definition'] + '\n' + banLogin.configured['threatInfo'] + '\n\n' + banLogin.configured['howtofix']
        if banLogin.device_hostname['must_report'] == True:
            toBeReturned = toBeReturned + banLogin.device_hostname['definition'] + '\n' + banLogin.device_hostname['threatInfo']+ '\n\n' + banLogin.device_hostname['howtofix']

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
                banExec.device_hostname = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3]),
                "cvss": (cvssMetrics)}

        if banExec.configured['must_report'] == True:
            toBeReturned = toBeReturned + banExec.configured['definition'] + '\n' + banExec.configured['threatInfo'] + '\n\n' + banExec.configured['howtofix'] + '\n'
        if banExec.device_hostname['must_report'] == True:
            toBeReturned = toBeReturned + banExec.device_hostname['definition'] + '\n' + banExec.device_hostname['threatInfo'] + '\n\n' + banExec.device_hostname['howtofix'] + '\n'

    return toBeReturned

def engine_services(lines, services):
    """Generic services assessment: password recovery, tcp/udp small servers, finger, bootp, ..."""
    try:
        services.pwd_recovery['cmdInCfg'] = search_string(lines, 'no service password-recovery')
    except AttributeError:
        pass

    if services.pwd_recovery['cmdInCfg'] is not None:
        # feature already configured
        services.pwd_recovery['must_report'] = False
    else:
        items = search_xml('pwd_recovery')
        if __builtin__.iosVersion >= 12.314:
            cvssMetrics = str(cvss_score(items[5]))
            services.pwd_recovery = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.314 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            services.pwd_recovery = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        services.tcp_small_servers['cmdInCfg'] = search_string(lines, 'no service tcp-small-servers')
    except AttributeError:
        pass

    if services.tcp_small_servers['cmdInCfg'] is not None:
        services.tcp_small_servers['must_report'] = False
    else:
        items = search_xml('tcp_small_servers')
        if __builtin__.iosVersion <= 12.0:
            cvssMetrics = str(cvss_score(items[5]))
            services.tcp_small_servers = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            cvssMetrics = str(cvss_score(items[5]))
            services.tcp_small_servers = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        services.udp_small_servers['cmdInCfg'] = search_string(lines, 'no service udp-small-servers')
    except AttributeError:
        pass

    if services.udp_small_servers['cmdInCfg'] is not None:
        services.udp_small_servers['must_report'] = False
    else:
        items = search_xml('udp_small_servers')
        if __builtin__.iosVersion <= 12.0:
            cvssMetrics = str(cvss_score(items[5]))
            services.udp_small_servers = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            cvssMetrics = str(cvss_score(items[5]))
            services.udp_small_servers = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        services.service_finger['cmdInCfg'] = search_string(lines, 'no service finger')
    except AttributeError:
        pass

    if services.service_finger['cmdInCfg'] is not None:
        services.service_finger['must_report'] = False
    else:
        items = search_xml('service_finger')
        if __builtin__.iosVersion <= 12.15:
            cvssMetrics = str(cvss_score(items[5]))
            services.service_finger = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            cvssMetrics = str(cvss_score(items[5]))
            services.service_finger = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        services.service_bootps['cmdInCfg'] = search_string(lines, 'no ip bootp server')
    except AttributeError:
        pass

    if services.service_bootps['cmdInCfg'] is not None:
        services.service_bootps['must_report'] = False
    else:
        items = search_xml('service_bootps')
        cvssMetrics = str(cvss_score(items[5]))
        services.service_bootps = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        services.service_tcpkeepalive_in['cmdInCfg'] = search_string(lines, 'service tcp-keepalive-in')
    except AttributeError:
        pass

    if services.service_tcpkeepalive_in['cmdInCfg'] is not None:
        services.service_tcpkeepalive_in['must_report'] = False
    else:
        items = search_xml('service_tcpkeepalive_in')
        cvssMetrics = str(cvss_score(items[5]))
        services.service_tcpkeepalive_in = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        services.service_tcpkeepalive_out['cmdInCfg'] = search_string(lines, 'service tcp-keepalive-out')
    except AttributeError:
        pass

    if services.service_tcpkeepalive_out['cmdInCfg'] is not None:
        services.service_tcpkeepalive_out['must_report'] = False
    else:
        items = search_xml('service_tcpkeepalive_out')
        cvssMetrics = str(cvss_score(items[5]))
        services.service_tcpkeepalive_out = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        services.service_ipdhcpboot_ignore['cmdInCfg'] = search_string(lines, 'ip dhcp bootp ignore')
    except AttributeError:
        pass

    if services.service_ipdhcpboot_ignore['cmdInCfg'] is not None:
        services.service_ipdhcpboot_ignore['must_report'] = False
    else:
        items = search_xml('service_ipdhcpboot_ignore')
        if __builtin__.iosVersion <= 12.228:
            cvssMetrics = str(cvss_score(items[5]))
            services.service_ipdhcpboot_ignore = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            cvssMetrics = str(cvss_score(items[5]))
            services.service_ipdhcpboot_ignore = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        services.service_dhcp['cmdInCfg'] = search_string(lines, 'no service dhcp')
    except AttributeError:
        pass

    if services.service_dhcp['cmdInCfg'] is not None:
        services.service_dhcp['must_report'] = False
    else:
        items = search_xml('service_dhcp')
        cvssMetrics = str(cvss_score(items[5]))
        services.service_dhcp = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        services.service_mop['cmdInCfg'] = search_string(lines, 'no service_mop enabled')
    except AttributeError:
        pass

    if services.service_mop['cmdInCfg'] is not None:
        services.service_mop['must_report'] = False
    else:
        items = search_xml('service_mop')
        cvssMetrics = str(cvss_score(items[5]))
        services.service_mop = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        services.ip_domain_lookup['cmdInCfg'] = search_string(lines, 'no ip domain-lookup')
    except AttributeError:
        pass

    if services.ip_domain_lookup['cmdInCfg'] is not None:
        services.ip_domain_lookup['must_report'] = False
    else:
        items = search_xml('ip_domain_lookup')
        cvssMetrics = str(cvss_score(items[5]))
        services.ip_domain_lookup = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        services.service_pad['cmdInCfg'] = search_string(lines, 'no service pad')
    except AttributeError:
        pass

    if services.service_pad['cmdInCfg'] is not None:
        services.service_pad['must_report'] = False
    else:
        items = search_xml('service_pad')
        cvssMetrics = str(cvss_score(items[5]))
        services.service_pad = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        services.service_http_server['cmdInCfg'] = search_string(lines, 'no ip http server')
    except AttributeError:
        pass

    if services.service_http_server['cmdInCfg'] is not None:
        services.service_http_server['must_report'] = False
    else:
        items = search_xml('service_http_server')
        cvssMetrics = str(cvss_score(items[5]))
        services.service_http_server = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        services.service_https_server['cmdInCfg'] = search_string(lines, 'no ip http secure-server')
    except AttributeError:
        pass

    if services.service_https_server['cmdInCfg'] is not None:
        services.service_https_server['must_report'] = False
    else:
        items = search_xml('service_https_server')
        cvssMetrics = str(cvss_score(items[5]))
        services.service_https_server = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        services.service_config['cmdInCfg'] = search_string(lines, 'no service config')
    except AttributeError:
        pass

    items = search_xml('service_config')
    if services.service_config['cmdInCfg'] is not None:
        services.service_config['must_report'] = False
    else:
        cvssMetrics = str(cvss_score(items[5]))
        services.service_config = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if services.pwd_recovery['must_report'] == True:
        toBeReturned = services.pwd_recovery['definition'] + '\n' + services.pwd_recovery['threatInfo'] + '\n\n' + services.pwd_recovery['howtofix'] + '\n'
    if services.tcp_small_servers['must_report'] == True:
        toBeReturned = toBeReturned + services.tcp_small_servers['definition'] + '\n' + services.tcp_small_servers['threatInfo'] + '\n\n' + services.tcp_small_servers['howtofix'] + '\n'
    if services.udp_small_servers['must_report'] == True:
        toBeReturned = toBeReturned + services.udp_small_servers['definition'] + '\n' + services.udp_small_servers['threatInfo'] + '\n\n' + services.udp_small_servers['howtofix'] + '\n'
    if services.service_finger['must_report'] == True:
        toBeReturned = toBeReturned + services.service_finger['definition'] + '\n' + services.service_finger['threatInfo'] + '\n\n' + services.service_finger['howtofix'] + '\n'
    if services.service_bootps['must_report'] == True:
        toBeReturned = toBeReturned + services.service_bootps['definition'] + '\n' + services.service_bootps['threatInfo'] + '\n\n' + services.service_bootps['howtofix'] + '\n'
    if services.service_tcpkeepalive_in['must_report'] == True:
        toBeReturned = toBeReturned + services.service_tcpkeepalive_in['definition'] + '\n' + services.service_tcpkeepalive_in['threatInfo'] + '\n\n' + services.service_tcpkeepalive_in['howtofix'] + '\n'
    if services.service_tcpkeepalive_out['must_report'] == True:
        toBeReturned = toBeReturned + services.service_tcpkeepalive_out['definition'] + '\n' + services.service_tcpkeepalive_out['threatInfo'] + '\n\n' + services.service_tcpkeepalive_out['howtofix'] + '\n'
    if services.service_ipdhcpboot_ignore['must_report'] == True:
        toBeReturned = toBeReturned + services.service_ipdhcpboot_ignore['definition'] + '\n' + services.service_ipdhcpboot_ignore['threatInfo'] + '\n\n' + services.service_ipdhcpboot_ignore['howtofix'] + '\n'
    if services.service_dhcp['must_report'] == True:
        toBeReturned = toBeReturned + services.service_dhcp['definition'] + '\n' + services.service_dhcp['threatInfo'] + '\n\n' + services.service_dhcp['howtofix'] + '\n'
    if services.service_mop['must_report'] == True:
        toBeReturned = toBeReturned + services.service_mop['definition'] + '\n' + services.service_mop['threatInfo'] + '\n\n' + services.service_mop['howtofix'] + '\n'
    if services.ip_domain_lookup['must_report'] == True:
        toBeReturned = toBeReturned + services.ip_domain_lookup['definition'] + '\n' + services.ip_domain_lookup['threatInfo'] + '\n\n' + services.ip_domain_lookup['howtofix'] + '\n'
    if services.service_pad['must_report'] == True:
        toBeReturned = toBeReturned + services.service_pad['definition'] + '\n' + services.service_pad['threatInfo'] + '\n\n' + services.service_pad['howtofix'] + '\n'
    if services.service_http_server['must_report'] == True:
        toBeReturned = toBeReturned + services.service_http_server['definition'] + '\n' + services.service_http_server['threatInfo'] + '\n\n' + services.service_http_server['howtofix'] + '\n'
    if services.service_https_server['must_report'] == True:
        toBeReturned = toBeReturned + services.service_https_server['definition'] + '\n' + services.service_https_server['threatInfo'] + '\n\n' + services.service_https_server['howtofix'] + '\n'
    if services.service_config['must_report'] == True:
        toBeReturned = toBeReturned + services.service_config['definition'] + '\n' + services.service_config['threatInfo'] + '\n\n' + services.service_config['howtofix'] + '\n'

    return toBeReturned

def engine_mem_cpu(lines, memCpu):
    """Memory and CPU configuration assessment."""

    try:
        memCpu.scheduler_allocate['cmdInCfg'] = search_string(lines, 'scheduler allocate 4000 400')
    except AttributeError:
        pass

    if memCpu.scheduler_allocate['cmdInCfg'] is None:
        memCpu.scheduler_allocate['must_report'] = True

    try:
        memCpu.scheduler_interval['cmdInCfg'] = search_string(lines, 'scheduler interval 500')
    except AttributeError:
        pass

    if memCpu.scheduler_interval['cmdInCfg'] is None:
        memCpu.scheduler_interval['must_report'] = True

    if memCpu.scheduler_allocate['must_report'] == True:
        items = search_xml('scheduler_allocate')
        cvssMetrics = str(cvss_score(items[5]))
        memCpu.scheduler_allocate = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    if memCpu.scheduler_interval['must_report'] == True:
        items = search_xml('scheduler_interval')
        cvssMetrics = str(cvss_score(items[5]))
        memCpu.scheduler_interval = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}


    try:
        memCpu.low_watermark_processor['cmdInCfg'] = search_string(lines, 'memory free low-watermark processor')
    except AttributeError:
        pass

    if memCpu.low_watermark_processor['cmdInCfg'] is not None:
        # feature already configured
        memCpu.low_watermark_processor['must_report'] = False
    else:
        items = search_xml('low_watermark_processor')
        if __builtin__.iosVersion >= 12.34:
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.low_watermark_processor = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.34 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.low_watermark_processor = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        memCpu.low_watermark_io['cmdInCfg'] = search_string(lines, 'memory free low-watermark io')
    except AttributeError:
        pass
    if memCpu.low_watermark_io['cmdInCfg'] is not None:
        # feature already configured
        memCpu.low_watermark_io['must_report'] = False
    else:
        items = search_xml('low_watermark_io')
        if __builtin__.iosVersion >= 12.34:
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.low_watermark_io = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.34 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.low_watermark_io = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        memCpu.mem_reserve_critical['cmdInCfg'] = search_string(lines, 'memory reserve critical')
    except AttributeError:
        pass
    if memCpu.mem_reserve_critical['cmdInCfg'] is not None:
        # feature already configured
        memCpu.mem_reserve_critical['must_report'] = False
    else:
        items = search_xml('mem_reserve_critical')
        if __builtin__.iosVersion >= 12.34:
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.mem_reserve_critical = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.34 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.mem_reserve_critical = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        memCpu.mem_reserve_console['cmdInCfg'] = search_string(lines, 'memory reserve console')
    except AttributeError:
        pass
    if memCpu.mem_reserve_console['cmdInCfg'] is not None:
        # feature already configured
        memCpu.mem_reserve_console['must_report'] = False
    else:
        items = search_xml('mem_reserve_console')
        if __builtin__.iosVersion >= 12.34:
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.mem_reserve_console = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.34 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.mem_reserve_console = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}


    try:
        memCpu.mem_ignore_overflow_io['cmdInCfg'] = search_string(lines, 'exception memory ignore overflow io')
    except AttributeError:
        pass
    if memCpu.mem_ignore_overflow_io['cmdInCfg'] is not None:
        # feature already configured
        memCpu.mem_ignore_overflow_io['must_report'] = False
    else:
        items = search_xml('memOverflowIo')
        if __builtin__.iosVersion >= 12.38:
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.mem_ignore_overflow_io = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.38 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.mem_ignore_overflow_io = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        memCpu.mem_ignore_overflow_cpu['cmdInCfg'] = search_string(lines, 'exception memory ignore overflow processor')
    except AttributeError:
        pass
    if memCpu.mem_ignore_overflow_cpu['cmdInCfg'] is not None:
        # feature already configured
        memCpu.mem_ignore_overflow_cpu['must_report'] = False
    else:
        items = search_xml('memOverflowProcessor')
        if __builtin__.iosVersion >= 12.38:
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.mem_ignore_overflow_cpu = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.38 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.mem_ignore_overflow_cpu = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}


    try:
        memCpu.cpu_threshold_notice['cmdSnmpserverTraps'] = search_string(lines, 'snmp-server enable traps cpu threshold')
    except AttributeError:
        pass
    try:
        memCpu.cpu_threshold_notice['cmdSnmpserverHost'] = search_re_string(lines, 'snmp-server host .* .* cpu')
    except AttributeError:
        pass
    try:
        memCpu.cpu_threshold_notice['cmdCpuThreshold'] = search_re_string(lines, 'process cpu threshold type .* rising .* interval')
    except AttributeError:
        pass
    try:
        memCpu.cpu_threshold_notice['cmdCpuStats'] = search_re_string(lines, 'process cpu statistics limit entry-percentage .*')
    except AttributeError:
        pass

    if ((memCpu.cpu_threshold_notice['cmdSnmpserverTraps'] is not None) and (memCpu.cpu_threshold_notice['cmdSnmpserverHost'] is not None) and (memCpu.cpu_threshold_notice['cmdCpuThreshold'] is not None) and (memCpu.cpu_threshold_notice['cmdCpuStats'] is not None) ):
        memCpu.cpu_threshold_notice['must_report'] = False
    else:
        items = search_xml('cpuThresholdNotification')
        if __builtin__.iosVersion >= 12.34:
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.cpu_threshold_notice = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.34 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            memCpu.cpu_threshold_notice = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    toBeReturned = ''
    if memCpu.scheduler_allocate['must_report'] == True:
        toBeReturned = toBeReturned + memCpu.scheduler_allocate['definition'] + '\n' + memCpu.scheduler_allocate['threatInfo'] + '\n\n' + memCpu.scheduler_allocate['howtofix'] + '\n'
    if memCpu.scheduler_interval['must_report'] == True:
        toBeReturned = toBeReturned + memCpu.scheduler_interval['definition'] + '\n' + memCpu.scheduler_interval['threatInfo'] + '\n\n' + memCpu.scheduler_interval['howtofix'] + '\n'
    if memCpu.low_watermark_processor['must_report'] == True:
        toBeReturned = memCpu.low_watermark_processor['definition'] + '\n' + memCpu.low_watermark_processor['threatInfo'] + '\n\n' + memCpu.low_watermark_processor['howtofix'] + '\n'
    if memCpu.low_watermark_io['must_report'] == True:
        toBeReturned = toBeReturned + memCpu.low_watermark_io['definition'] + '\n' + memCpu.low_watermark_io['threatInfo'] + '\n\n' + memCpu.low_watermark_io['howtofix'] + '\n'
    if memCpu.mem_reserve_critical['must_report'] == True:
        toBeReturned = toBeReturned + memCpu.mem_reserve_critical['definition'] + '\n' + memCpu.mem_reserve_critical['threatInfo'] + '\n\n' + memCpu.mem_reserve_critical['howtofix'] + '\n'
    if memCpu.mem_reserve_console['must_report'] == True:
        toBeReturned = toBeReturned + memCpu.mem_reserve_console['definition'] + '\n' + memCpu.mem_reserve_console['threatInfo'] + '\n\n' + memCpu.mem_reserve_console['howtofix'] + '\n'
    if memCpu.mem_ignore_overflow_io['must_report'] == True:
        toBeReturned = toBeReturned + memCpu.mem_ignore_overflow_io['definition'] + '\n' + memCpu.mem_ignore_overflow_io['threatInfo'] + '\n\n' + memCpu.mem_ignore_overflow_io['howtofix'] + '\n'
    if memCpu.mem_ignore_overflow_cpu['must_report'] == True:
        toBeReturned = toBeReturned + memCpu.mem_ignore_overflow_cpu['definition'] + '\n' + memCpu.mem_ignore_overflow_cpu['threatInfo'] + '\n\n' + memCpu.mem_ignore_overflow_cpu['howtofix'] + '\n'
    if memCpu.cpu_threshold_notice['must_report'] == True:
        toBeReturned = toBeReturned + memCpu.cpu_threshold_notice['definition'] + '\n' + memCpu.cpu_threshold_notice['threatInfo'] + '\n\n' + memCpu.cpu_threshold_notice['howtofix'] + '\n'

    return toBeReturned

def engine_crashinfo(lines, crashinfo):
    """Crashinfo generation configuration assessment."""
    try:
        crashinfo.crashinfo_max_files['cmdInCfg'] = search_string(lines, 'exception crashinfo maximum files')
    except AttributeError:
        pass
    if crashinfo.crashinfo_max_files['cmdInCfg'] is not None:
        # feature already configured
        crashinfo.crashinfo_max_files['must_report'] = False
    else:
        items = search_xml('ExceptionMaximumFiles')
        cvssMetrics = str(cvss_score(items[5]))
        crashinfo.crashinfo_max_files = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if crashinfo.crashinfo_max_files['must_report'] == True:
        toBeReturned = crashinfo.crashinfo_max_files['definition'] + '\n' + crashinfo.crashinfo_max_files['threatInfo'] + '\n\n' + crashinfo.crashinfo_max_files['howtofix'] + '\n'
    return toBeReturned

def engine_mpp(lines, vtyList, vtyCfg, mpp):
    """Management plane protection assessment."""

    if len(vtyList) == 0:
        # if all vty are removed
        mpp.mgmt_interfaces['must_report'] = False
        mpp.sshserver['must_report'] = False
        mpp.scp_server['must_report'] = False
        return

    for i in range(0, len(vtyCfg)):
        for k in range (0, len(vtyCfg[i])):
            if search_string(vtyCfg[i][k], 'transport input none') is not None:
                mpp.mgmt_interfaces['must_report'] = False
                mpp.sshserver['must_report'] = False
                mpp.scp_server['must_report'] = False
                return
    if __builtin__.deviceType == 'router':
        try:
            mpp.mgmt_interfaces['cpHostCfg'] = search_string(lines, 'control-plane host')
        except AttributeError:
            pass
        try:
            mpp.mgmt_interfaces['mgmtIfaceCfg'] = search_re_string(lines, 'management-interface .* allow .*')
        except AttributeError:
            pass

        if mpp.mgmt_interfaces['cpHostCfg'] is not None:
            if mpp.mgmt_interfaces['mgmtIfaceCfg'] is not None:
                mpp.mgmt_interfaces['must_report'] = False
            else:
                if __builtin__.iosVersion >= 12.46:
                    items = search_xml('ManagementPlaneProtection')
                    cvssMetrics = str(cvss_score(items[5]))
                    mpp.mgmt_interfaces = {
                    "must_report": True,
                    "fixImpact": (items[0]),
                    "definition": (items[1]),
                    "threatInfo": (items[2]),
                    "howtofix": (items[3]),
                    "cvss": (cvssMetrics)}
                else:
                    items = search_xml('ManagementPlaneProtection')
                    cvssMetrics = str(cvss_score(items[5]))
                    mpp.mgmt_interfaces = {
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
                mpp.mgmt_interfaces = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3]),
                "cvss": (cvssMetrics)}
            else:
                items = search_xml('ManagementPlaneProtection')
                cvssMetrics = str(cvss_score(items[5]))
                mpp.mgmt_interfaces = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[4]),
                "cvss": (cvssMetrics)}

    try:
        mpp.ssh_server_timeout['timeout'] = search_string(lines, 'ip ssh time-out')
    except AttributeError:
        pass
    try:
        mpp.ssh_server_auth_retries['authRetries'] = search_string(lines, 'ip ssh authentication-retries')
    except AttributeError:
        pass
    try:
        mpp.ssh_server_src_interface['sourceinterface'] = search_string(lines, 'ip ssh source-interface')
    except AttributeError:
        pass

    if mpp.ssh_server_timeout['timeout'] is None:
        items = search_xml('ssh_server_timeout')
        cvssMetrics = str(cvss_score(items[5]))
        mpp.ssh_server_timeout = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        mpp.ssh_server_timeout['must_report'] = False

    if mpp.ssh_server_auth_retries['authRetries'] is None:
        items = search_xml('ssh_server_auth_retries')
        cvssMetrics = str(cvss_score(items[5]))
        mpp.ssh_server_auth_retries = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        mpp.ssh_server_auth_retries['must_report'] = False

    if mpp.ssh_server_src_interface['sourceinterface'] is None:
        items = search_xml('sshserverSourceIf')
        cvssMetrics = str(cvss_score(items[5]))
        mpp.ssh_server_src_interface = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        mpp.ssh_server_src_interface['must_report'] = False

    try:
        mpp.scp_server['cmdIncfg'] = search_string(lines, 'ip scp server enable')
    except AttributeError:
        pass

    if mpp.scp_server['cmdIncfg'] is None:
        items = search_xml('sshscp_server')
        cvssMetrics = str(cvss_score(items[5]))
        mpp.scp_server = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        mpp.scp_server['must_report'] = False

    try:
        mpp.http_secure_server['cmdIncfg'] = search_string(lines, 'ip http server')
    except AttributeError:
        pass

    if mpp.http_secure_server['cmdIncfg'] is not None:
        items = search_xml('HTTPserver')
        cvssMetrics = str(cvss_score(items[5]))
        mpp.http_secure_server = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        mpp.http_secure_server['must_report'] = False

    try:
        mpp.login_bruteforce['blockfor'] = search_string(lines, 'login block-for')
    except AttributeError:
        pass
    try:
        mpp.login_bruteforce['delay'] = search_string(lines, 'login delay')
    except AttributeError:
        pass
    try:
        mpp.login_bruteforce['quietacl'] = search_string(lines, 'login quiet access-class')
    except AttributeError:
        pass
    try:
        mpp.login_bruteforce['faillog'] = search_string(lines, 'login on-failure log every')
    except AttributeError:
        pass
    try:
        mpp.login_bruteforce['successlog'] = search_string(lines, 'login on-success log every')
    except AttributeError:
        pass
    login_bruteforceCount = 0
    if mpp.login_bruteforce['blockfor'] is not None:
        login_bruteforceCount = login_bruteforceCount + 1
    if mpp.login_bruteforce['delay'] is not None:
        login_bruteforceCount = login_bruteforceCount + 1
    if mpp.login_bruteforce['quietacl'] is not None:
        login_bruteforceCount = login_bruteforceCount + 1
    if mpp.login_bruteforce['faillog'] is not None:
        login_bruteforceCount = login_bruteforceCount + 1
    if mpp.login_bruteforce['successlog'] is not None:
        login_bruteforceCount = login_bruteforceCount + 1

    if login_bruteforceCount < 5:
        if __builtin__.iosVersion >= 12.34:
            items = search_xml('login_bruteforce')
            cvssMetrics = str(cvss_score(items[5]))
            mpp.login_bruteforce = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.3.4 to get the feature
            items = search_xml('login_bruteforce')
            cvssMetrics = str(cvss_score(items[5]))
            mpp.login_bruteforce = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}
    else:
        mpp.login_bruteforce['must_report'] = False

    toBeReturned = ''
    if mpp.mgmt_interfaces['must_report'] == True:
        toBeReturned = mpp.mgmt_interfaces['definition'] + '\n' + mpp.mgmt_interfaces['threatInfo'] + '\n\n' + mpp.mgmt_interfaces['howtofix'] + '\n'
    if mpp.ssh_server_timeout['must_report'] == True:
        toBeReturned = toBeReturned + mpp.ssh_server_timeout['definition'] + '\n' + mpp.ssh_server_timeout['threatInfo'] + '\n\n' + mpp.ssh_server_timeout['howtofix'] + '\n'
    if mpp.ssh_server_auth_retries['must_report'] == True:
        toBeReturned = toBeReturned + mpp.ssh_server_auth_retries['definition'] + '\n' + mpp.ssh_server_auth_retries['threatInfo'] + '\n\n' + mpp.ssh_server_auth_retries['howtofix'] + '\n'
    if mpp.ssh_server_src_interface['must_report'] == True:
        toBeReturned = toBeReturned + mpp.ssh_server_src_interface['definition'] + '\n' + mpp.ssh_server_src_interface['threatInfo'] + '\n\n' + mpp.ssh_server_src_interface['howtofix'] + '\n'
    if mpp.scp_server['must_report'] == True:
        toBeReturned = toBeReturned + mpp.scp_server['definition'] + '\n' + mpp.scp_server['threatInfo'] + '\n\n' + mpp.scp_server['howtofix'] + '\n'
    if mpp.http_secure_server['must_report'] == True:
        toBeReturned = toBeReturned + mpp.http_secure_server['definition'] + '\n' + mpp.http_secure_server['threatInfo'] + '\n\n' + mpp.http_secure_server['howtofix'] + '\n'
    if mpp.login_bruteforce['must_report'] == True:
        toBeReturned = toBeReturned + mpp.login_bruteforce['definition'] + '\n' + mpp.login_bruteforce['threatInfo'] + '\n\n' + mpp.login_bruteforce['howtofix'] + '\n'

    return toBeReturned

def engine_password_management(lines, pwdManagement):
    """Access management assessment."""
    try:
        pwdManagement.enable_secret['cmdInCfg'] = search_string(lines, 'enable secret')
    except AttributeError:
        pass
    if pwdManagement.enable_secret['cmdInCfg'] is not None:
        # feature already configured
        pwdManagement.enable_secret['must_report'] = False
    else:
        items = search_xml('enable_secret')
        cvssMetrics = str(cvss_score(items[5]))
        pwdManagement.enable_secret = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        pwdManagement.service_password_encryption['cmdInCfg'] = search_re_string(lines, '^service password-encryption')
    except AttributeError:
        pass
    if pwdManagement.service_password_encryption['cmdInCfg'] is not None:
        # feature already configured
        pwdManagement.service_password_encryption['must_report'] = False
    else:
        items = search_xml('servicePasswordEncryption')
        cvssMetrics = str(cvss_score(items[5]))
        pwdManagement.service_password_encryption = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    try:
        pwdManagement.username_secret['cmdInCfg'] = search_re_string(lines, '^username .* password .*')
    except AttributeError:
        pass
    if pwdManagement.username_secret['cmdInCfg'] is None:
        # feature already configured or not used
        pwdManagement.username_secret['must_report'] = False
    else:
        items = search_xml('username_secret')
        if __builtin__.iosVersion >= 12.28:
            cvssMetrics = str(cvss_score(items[5]))
            pwdManagement.username_secret = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            cvssMetrics = str(cvss_score(items[5]))
            pwdManagement.username_secret = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        pwdManagement.retry_lockout['aaa_new_model'] = search_re_string(lines, '^aaa new-model')
    except AttributeError:
        pass
    try:
        pwdManagement.retry_lockout['usernames'] = search_re_string(lines, '^username .*')
    except AttributeError:
        pass
    try:
        pwdManagement.retry_lockout['maxFail'] = search_string(lines, 'aaa local authentication attempts max-fail')
    except AttributeError:
        pass
    try:
        pwdManagement.retry_lockout['aaaAuthLoginLocal'] = search_re_string(lines, 'aaa authentication login default (local|.*) ?local')
    except AttributeError:
        pass

    if ((pwdManagement.retry_lockout['aaa_new_model'] is not None) and (pwdManagement.retry_lockout['maxFail'] is not None) and (pwdManagement.retry_lockout['aaaAuthLoginLocal'] is not None) ):
        pwdManagement.retry_lockout['must_report'] = False
    elif pwdManagement.retry_lockout['usernames'] is None:
        pwdManagement.retry_lockout['must_report'] = False
    else:
        items = search_xml('retry_lockout')
        if __builtin__.iosVersion >= 12.314:
            cvssMetrics = str(cvss_score(items[5]))
            pwdManagement.retry_lockout = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.314 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            pwdManagement.retry_lockout = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    toBeReturned = ''
    if pwdManagement.enable_secret['must_report'] == True:
        toBeReturned = pwdManagement.enable_secret['definition'] + '\n' + pwdManagement.enable_secret['threatInfo'] + '\n\n' + pwdManagement.enable_secret['howtofix'] + '\n'
    if pwdManagement.service_password_encryption['must_report'] == True:
        toBeReturned = toBeReturned + pwdManagement.service_password_encryption['definition'] + '\n' + pwdManagement.service_password_encryption['threatInfo'] + '\n\n' + pwdManagement.service_password_encryption['howtofix'] + '\n'
    if pwdManagement.username_secret['must_report'] == True:
        toBeReturned = toBeReturned + pwdManagement.username_secret['definition'] + '\n' + pwdManagement.username_secret['threatInfo'] + '\n\n' + pwdManagement.username_secret['howtofix'] + '\n'
    if pwdManagement.retry_lockout['must_report'] == True:
        toBeReturned = toBeReturned + pwdManagement.retry_lockout['definition'] + '\n' + pwdManagement.retry_lockout['threatInfo'] + '\n\n' + pwdManagement.retry_lockout['howtofix'] + '\n'

    return toBeReturned

def engine_tacacs(lines, tacacs, mode):
    """Tacacs+ assessment."""
    toBeReturned = ''
    try:
        tacacs.aaa_new_model['cmdInCfg'] = search_string(lines, 'aaa new-model')
    except AttributeError:
        pass

    if mode == 'Authentication':

        try:
            tacacs.auth_tacacs['cmdInCfg'] = search_re_string(lines, 'aaa authentication login default (group tacacs\+|.*) ?tacacs\+')
        except AttributeError:
            pass

        try:
            tacacs.auth_fallback['cmdInCfg'] = search_re_string(lines, 'aaa authentication login default (group tacacs\+|.*) (enable|local)')
        except AttributeError:
            pass

        if tacacs.aaa_new_model['cmdInCfg'] is None:
            items = search_xml('aaa_new_model')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.aaa_new_model = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.aaa_new_model['must_report'] = False

        if tacacs.auth_tacacs['cmdInCfg'] is None:
            items = search_xml('aaaauth_tacacs')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.auth_tacacs = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.auth_tacacs['must_report'] = False

        if tacacs.auth_fallback['cmdInCfg'] is None:
            items = search_xml('aaaauth_tacacsFallback')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.auth_fallback = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.auth_fallback['must_report'] = False

    elif mode == 'Authorization':

        try:
            tacacs.auth_exec['cmdInCfg'] = search_string(lines, 'aaa authorization exec default group tacacs none')
        except AttributeError:
            pass

        try:
            tacacs.level_0['cmdInCfg'] = search_string(lines, 'aaa authorization commands 0 default group tacacs none')
        except AttributeError:
            pass

        try:
            tacacs.level_1['cmdInCfg'] = search_string(lines, 'aaa authorization commands 1 default group tacacs none')
        except AttributeError:
            pass

        try:
            tacacs.level_15['cmdInCfg'] = search_string(lines, 'aaa authorization commands 15 default group tacacs none')
        except AttributeError:
            pass

        if tacacs.auth_exec['cmdInCfg'] is None:
            items = search_xml('aaaauth_tacacsExec')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.auth_exec = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.auth_exec['must_report'] = False

        if tacacs.level_0['cmdInCfg'] is None:
            items = search_xml('aaaauth_tacacslevel_0')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.level_0 = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.level_0['must_report'] = False

        if tacacs.level_1['cmdInCfg'] is None:
            items = search_xml('aaaauth_tacacslevel_1')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.level_1 = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.level_1['must_report'] = False

        if tacacs.level_15['cmdInCfg'] is None:
            items = search_xml('aaaauth_tacacslevel_15')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.level_15 = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.level_15['must_report'] = False

    elif mode == 'Accounting':

        try:
            tacacs.aaa_accounting['cmdInCfg'] = search_string(lines, 'aaa accounting exec default start-stop group tacacs')
        except AttributeError:
            pass

        try:
            tacacs.level_0['cmdInCfg'] = search_string(lines, 'aaa accounting commands 0 default start-stop group tacacs')
        except AttributeError:
            pass

        try:
            tacacs.level_1['cmdInCfg'] = search_string(lines, 'aaa accounting commands 1 default start-stop group tacacs')
        except AttributeError:
            pass

        try:
            tacacs.level_15['cmdInCfg'] = search_string(lines, 'aaa accounting commands 15 default start-stop group tacacs')
        except AttributeError:
            pass

        if tacacs.aaa_accounting['cmdInCfg'] is None:
            items = search_xml('aaaAccountingTacacsExec')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.aaa_accounting = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.aaa_accounting['must_report'] = False

        if tacacs.level_0['cmdInCfg'] is None:
            items = search_xml('aaaAccountingTacacslevel_0')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.level_0 = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.level_0['must_report'] = False

        if tacacs.level_1['cmdInCfg'] is None:
            items = search_xml('aaaAccountingTacacslevel_1')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.level_1 = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.level_1['must_report'] = False

        if tacacs.level_15['cmdInCfg'] is None:
            items = search_xml('aaaAccountingTacacslevel_15')
            cvssMetrics = str(cvss_score(items[5]))
            tacacs.level_15 = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            tacacs.level_15['must_report'] = False

    elif mode == 'RedundantAAA':

        countservers = 0
        for line in lines:
            if search_string(lines, 'tacacs-server host') is not None:
                countservers = countservers +1

        if countservers >= 2:
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
        if tacacs.aaa_new_model['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.aaa_new_model['definition'] + '\n' + tacacs.aaa_new_model['threatInfo'] + '\n\n' + tacacs.aaa_new_model['howtofix'] + '\n'
        if tacacs.auth_tacacs['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.auth_tacacs['definition'] + '\n' + tacacs.auth_tacacs['threatInfo'] + '\n\n' + tacacs.auth_tacacs['howtofix'] + '\n'
        if tacacs.auth_fallback['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.auth_fallback['definition'] + '\n' + tacacs.auth_fallback['threatInfo'] + '\n\n' + tacacs.auth_fallback['howtofix'] + '\n'
    elif mode == 'Authorization':
        if tacacs.auth_exec['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.auth_exec['definition'] + '\n' + tacacs.auth_exec['threatInfo'] + '\n\n' + tacacs.auth_exec['howtofix'] + '\n'
        if tacacs.level_0['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.level_0['definition'] + '\n' + tacacs.level_0['threatInfo'] + '\n\n' + tacacs.level_0['howtofix'] + '\n'
        if tacacs.level_1['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.level_1['definition'] + '\n' + tacacs.level_1['threatInfo'] + '\n\n' + tacacs.level_1['howtofix'] + '\n'
        if tacacs.level_15['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.level_15['definition'] + '\n' + tacacs.level_15['threatInfo'] + '\n\n' + tacacs.level_15['howtofix'] + '\n'
    elif mode == 'Accounting':
        if tacacs.aaa_accounting['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.aaa_accounting['definition'] + '\n' + tacacs.aaa_accounting['threatInfo'] + '\n\n' + tacacs.aaa_accounting['howtofix'] + '\n'
        if tacacs.level_0['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.level_0['definition'] + '\n' + tacacs.level_0['threatInfo'] + '\n\n' + tacacs.level_0['howtofix'] + '\n'
        if tacacs.level_1['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.level_1['definition'] + '\n' + tacacs.level_1['threatInfo'] + '\n\n' + tacacs.level_1['howtofix'] + '\n'
        if tacacs.level_15['must_report'] == True:
            toBeReturned = toBeReturned + tacacs.level_15['definition'] + '\n' + tacacs.level_15['threatInfo'] + '\n\n' + tacacs.level_15['howtofix'] + '\n'

    return toBeReturned

def engine_snmp(lines, snmp):
    """SNMP configuration assessment."""
    try:
        snmp.ro_community['cmdInCfg'] = search_re_string(lines, 'snmp-server community .* (RO|ro)')
    except AttributeError:
        pass

    try:
        snmp.rw_community['cmdInCfg'] = search_re_string(lines, 'snmp-server community .* (RW|rw)')
    except AttributeError:
        pass

    try:
        snmp.view_ro_community['cmdInCfg'] = search_re_string(lines, 'snmp-server community .* view .* (RO|ro)')
    except AttributeError:
        pass

    try:
        snmp.view_rw_community['cmdInCfg'] = search_re_string(lines, 'snmp-server community .* view .* (RW|rw)')
    except AttributeError:
        pass

    try:
        snmp.snmp_v3['cmdInCfg'] = search_re_string(lines, 'snmp-server group .* v3 (auth|priv)')
    except AttributeError:
        pass

    try:
        mgmtSubnet = __builtin__.ipv4_mgmt_outbound[0][0]
    except TypeError:
        mgmtSubnet = ""
        pass
    try:
        mgmtWildcardMask = __builtin__.ipv4_mgmt_outbound[0][3]
    except TypeError:
        mgmtWildcardMask = ""
        pass

    if snmp.ro_community['cmdInCfg'] is None:
        # feature not configured
        snmp.ro_community['must_report'] = False
        snmp.ro_community_acl['must_report'] = False
    else:
        SNMPcommunity = snmp.ro_community['cmdInCfg'].split(' ')
        ROsecure = snmp_community_complexity(SNMPcommunity[2])
        if ROsecure == False:
            items = search_xml('snmpro_communityHardened')
            cvssMetrics = str(cvss_score(items[5]))
            snmp.ro_community = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
                .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
            "cvss": (cvssMetrics)}
        try:
            snmp.ro_community_acl['cmdInCfg'] = search_re_string(lines, 'snmp-server community .* (RO|ro) \d')
        except AttributeError:
            pass

        if snmp.ro_community_acl['cmdInCfg'] is None:
            items = search_xml('snmpro_communityHardenedACL')
            cvssMetrics = str(cvss_score(items[5]))
            snmp.ro_community_acl = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
                .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
            "cvss": (cvssMetrics)}
        else:
            accessListNumber = snmp.ro_community_acl['cmdInCfg'].split(' ')[4]
            if check_std_acl(lines, accessListNumber) == True:
                snmp.ro_community_acl['must_report'] = False
            else:
                items = search_xml('snmpro_communityHardenedACL')
                cvssMetrics = str(cvss_score(items[5]))
                snmp.ro_community_acl = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3].strip() \
                    .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                    .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
                "cvss": (cvssMetrics)}

    if snmp.rw_community['cmdInCfg'] is None:
        # feature not configured
        snmp.rw_community['must_report'] = False
        snmp.rw_community_acl['must_report'] = False
    else:
        SNMPcommunity = snmp.rw_community['cmdInCfg'].split(' ')
        RWsecure = snmp_community_complexity(SNMPcommunity[2])
        if RWsecure == False:
            items = search_xml('snmprw_communityHardened')
            cvssMetrics = str(cvss_score(items[5]))
            snmp.rw_community = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
                .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
            "cvss": (cvssMetrics)}
        try:
            snmp.rw_community_acl['cmdInCfg'] = search_re_string(lines, 'snmp-server community .* (RW|rw) \d')
        except AttributeError:
            pass

        if snmp.rw_community_acl['cmdInCfg'] is None:
            items = search_xml('snmprw_communityHardenedACL')
            cvssMetrics = str(cvss_score(items[5]))
            snmp.rw_community_acl = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
                .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
            "cvss": (cvssMetrics)}
        else:
            accessListNumber = snmp.rw_community_acl['cmdInCfg'].split(' ')[4]
            if check_std_acl(lines, accessListNumber) == True:
                snmp.rw_community_acl['must_report'] = False
            else:
                items = search_xml('snmprw_communityHardenedACL')
                cvssMetrics = str(cvss_score(items[5]))
                snmp.rw_community_acl = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3].strip() \
                    .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                    .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
                "cvss": (cvssMetrics)}

    if snmp.view_ro_community['cmdInCfg'] is None:
        # feature not configured
        snmp.view_ro_community['must_report'] = False
        snmp.view_ro_community_acl['must_report'] = False
    else:
        SNMPcommunity = snmp.view_ro_community['cmdInCfg'].split(' ')
        ROsecure = snmp_community_complexity(SNMPcommunity[2])
        if ROsecure == False:
            items = search_xml('Viewsnmpro_communityHardened')
            cvssMetrics = str(cvss_score(items[5]))
            snmp.view_ro_community = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
                .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
            "cvss": (cvssMetrics)}
        try:
            snmp.view_ro_community_acl['cmdInCfg'] = search_re_string(lines, 'snmp-server community .* view .* (RO|ro) \d')
        except AttributeError:
            pass

        if snmp.view_ro_community_acl['cmdInCfg'] is None:
            items = search_xml('Viewsnmpro_communityHardenedACL')
            cvssMetrics = str(cvss_score(items[5]))
            snmp.view_ro_community_acl = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
                .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
            "cvss": (cvssMetrics)}
        else:
            accessListNumber = snmp.view_ro_community_acl['cmdInCfg'].split(' ')[4]
            if check_std_acl(lines, accessListNumber) == True:
                snmp.view_ro_community_acl['must_report'] = False
            else:
                items = search_xml('Viewsnmpro_communityHardenedACL')
                cvssMetrics = str(cvss_score(items[5]))
                snmp.view_ro_community_acl = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3].strip() \
                    .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                    .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
                "cvss": (cvssMetrics)}

    if snmp.view_rw_community['cmdInCfg'] is None:
        # feature not configured
        snmp.view_rw_community['must_report'] = False
        snmp.view_rw_community_acl['must_report'] = False
    else:
        SNMPcommunity = snmp.view_rw_community['cmdInCfg'].split(' ')
        RWsecure = snmp_community_complexity(SNMPcommunity[2])
        if RWsecure == False:
            items = search_xml('Viewsnmprw_communityHardened')
            cvssMetrics = str(cvss_score(items[5]))
            snmp.view_rw_community = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
                .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
            "cvss": (cvssMetrics)}
        try:
            snmp.view_rw_community_acl['cmdInCfg'] = search_re_string(lines, 'snmp-server community .* view .* (RW|rw) \d')
        except AttributeError:
            pass

        if snmp.view_rw_community_acl['cmdInCfg'] is None:
            items = search_xml('snmprw_communityHardenedACL')
            cvssMetrics = str(cvss_score(items[5]))
            snmp.view_rw_community_acl = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
            .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
            .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
            "cvss": (cvssMetrics)}
        else:
            accessListNumber = snmp.view_rw_community_acl['cmdInCfg'].split(' ')[4]
            if check_std_acl(lines, accessListNumber) == True:
                snmp.view_rw_community_acl['must_report'] = False
            else:
                items = search_xml('Viewsnmprw_communityHardenedACL')
                cvssMetrics = str(cvss_score(items[5]))
                snmp.view_rw_community_acl = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3].strip() \
                    .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
                    .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
                "cvss": (cvssMetrics)}

    if snmp.snmp_v3['cmdInCfg'] is None:
        # feature not configured
        items = search_xml('snmpVersion3')
        cvssMetrics = str(cvss_score(items[5]))
        snmp.snmp_v3 = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3].strip() \
            .replace('[%ManagementSubnet]', mgmtSubnet, 1) \
            .replace('[%ManagementWildcardMask]', mgmtWildcardMask, 1)),
        "cvss": (cvssMetrics)}

    else:
        snmp.snmp_v3['must_report'] = False

    toBeReturned = ''
    if snmp.ro_community['must_report'] == True:
        toBeReturned = snmp.ro_community['definition'] + '\n' + snmp.ro_community['threatInfo'] + '\n\n' + snmp.ro_community['howtofix'] + '\n'
    if snmp.ro_community_acl['must_report'] == True:
        toBeReturned = toBeReturned + snmp.ro_community_acl['definition'] + '\n' + snmp.ro_community_acl['threatInfo'] + '\n\n' + snmp.ro_community_acl['howtofix'] + '\n'
    if snmp.rw_community['must_report'] == True:
        toBeReturned = toBeReturned + snmp.rw_community['definition'] + '\n' + snmp.rw_community['threatInfo'] + '\n\n' + snmp.rw_community['howtofix'] + '\n'
    if snmp.rw_community_acl['must_report'] == True:
        toBeReturned = toBeReturned + snmp.rw_community_acl['definition'] + '\n' + snmp.rw_community_acl['threatInfo'] + '\n\n' + snmp.rw_community_acl['howtofix'] + '\n'
    if snmp.view_ro_community['must_report'] == True:
        toBeReturned = toBeReturned + snmp.view_ro_community['definition'] + '\n' + snmp.view_ro_community['threatInfo'] + '\n\n' + snmp.view_ro_community['howtofix'] + '\n'
    if snmp.view_ro_community_acl['must_report'] == True:
        toBeReturned = toBeReturned + snmp.view_ro_community_acl['definition'] + '\n' + snmp.view_ro_community_acl['threatInfo'] + '\n\n' + snmp.view_ro_community_acl['howtofix'] + '\n'
    if snmp.view_rw_community['must_report'] == True:
        toBeReturned = toBeReturned + snmp.view_rw_community['definition'] + '\n' + snmp.view_rw_community['threatInfo'] + '\n\n' + snmp.view_rw_community['howtofix'] + '\n'
    if snmp.view_rw_community_acl['must_report'] == True:
        toBeReturned = toBeReturned + snmp.view_rw_community_acl['definition'] + '\n' + snmp.view_rw_community_acl['threatInfo'] + '\n\n' + snmp.view_rw_community_acl['howtofix'] + '\n'
    if snmp.snmp_v3['must_report'] == True:
        toBeReturned = toBeReturned + snmp.snmp_v3['definition'] + '\n' + snmp.snmp_v3['threatInfo'] + '\n\n' + snmp.snmp_v3['howtofix'] + '\n'

    return toBeReturned

def engine_syslog(lines, syslog):
    """Syslog assessment."""
    try:
        syslog.server['cmdInCfg'] = search_string(lines, 'logging host')
    except AttributeError:
        pass

    if syslog.server['cmdInCfg'] is None:
        # feature not configured
        try:
            mgmtSubnet = __builtin__.ipv4_mgmt_outbound[0][0]
        except TypeError:
            mgmtSubnet = ""
            pass
        try:
            mgmtWildcardMask = __builtin__.ipv4_mgmt_outbound[0][3]
        except TypeError:
            mgmtWildcardMask = ""
            pass


        items = search_xml('syslogserver')
        cvssMetrics = str(cvss_score(items[5]))

        if len(mgmtSubnet) > 0:
            syslog.server = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
                .replace('[%ManagementSyslog]', mgmtSubnet, 1)),
            "cvss": (cvssMetrics)}
        else:
            syslog.server = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3].strip() \
                .replace('[%ManagementSyslog]', 'new-syslog-server', 1)),
            "cvss": (cvssMetrics)}

    else:
        syslog.server['must_report'] = False

    try:
        syslog.level_trap['cmdInCfg'] = search_string(lines, 'logging trap')
    except AttributeError:
        pass
    if syslog.level_trap['cmdInCfg'] is None:
        # feature not configured
        items = search_xml('sysloglevel_trap')
        cvssMetrics = str(cvss_score(items[5]))
        syslog.level_trap = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        level = syslog.level_trap['cmdInCfg'].split(' ')[2]
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
            syslog.level_trap['must_report'] = False
        else:
            items = search_xml('sysloglevel_trap')
            cvssMetrics = str(cvss_score(items[5]))
            syslog.level_trap = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}

    try:
        syslog.level_buffered['cmdInCfg'] = search_re_string(lines, 'logging buffered \d')
    except AttributeError:
        pass
    if syslog.level_buffered['cmdInCfg'] is None:
        # feature not configured
        items = search_xml('sysloglevel_buffered')
        cvssMetrics = str(cvss_score(items[5]))
        syslog.level_buffered = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        level = syslog.level_buffered['cmdInCfg'].split(' ')[2]
        if int(level) == 6:
            syslog.level_buffered['must_report'] = False
        else:
            items = search_xml('sysloglevel_buffered')
            cvssMetrics = str(cvss_score(items[5]))
            syslog.level_buffered = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}

    try:
        syslog.logging_console['cmdInCfg'] = search_string(lines, 'no logging console')
    except AttributeError:
        pass
    if syslog.logging_console['cmdInCfg'] is None:
        # feature not configured
        items = search_xml('syslogConsole')
        cvssMetrics = str(cvss_score(items[5]))
        syslog.logging_console = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        syslog.logging_console['must_report'] = False

    try:
        syslog.logging_monitor['cmdInCfg'] = search_string(lines, 'no logging monitor')
    except AttributeError:
        pass
    if syslog.logging_monitor['cmdInCfg'] is None:
        # feature not configured
        items = search_xml('syslogMonitor')
        cvssMetrics = str(cvss_score(items[5]))
        syslog.logging_monitor = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        syslog.logging_monitor['must_report'] = False

    try:
        syslog.logging_buffered['cmdInCfg'] = search_re_string(lines, 'logging buffered .* .*')
    except AttributeError:
        pass
    if syslog.logging_buffered['cmdInCfg'] is None:
        # feature not configured
        items = search_xml('syslogBuffered')
        cvssMetrics = str(cvss_score(items[5]))
        syslog.logging_buffered = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        size = syslog.logging_buffered['cmdInCfg'].split(' ')[2]
        level = syslog.logging_buffered['cmdInCfg'].split(' ')[3]
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
            syslog.logging_buffered['must_report'] = False
        else:
            items = search_xml('syslogBuffered')
            cvssMetrics = str(cvss_score(items[5]))
            syslog.logging_buffered = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}

    try:
        syslog.interface['cmdInCfg'] = search_string(lines, 'logging source-interface loopback')
    except AttributeError:
        pass
    if syslog.interface['cmdInCfg'] is None:
        # feature not configured
        items = search_xml('sysloginterface')
        cvssMetrics = str(cvss_score(items[5]))
        syslog.interface = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    else:
        syslog.interface['must_report'] = False

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
            syslog.server_arp['cmdInCfg'] = search_string(lines, 'logging server-arp')
        except AttributeError:
            pass
        if syslog.server_arp['cmdInCfg'] is None:
            # feature not configured
            if __builtin__.iosVersion >= 12.3:
                items = search_xml('syslogserver_arp')
                cvssMetrics = str(cvss_score(items[5]))
                syslog.server_arp = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[3]),
                "cvss": (cvssMetrics)}
            else:
                # upgrade to >= 12.3 to get the feature
                items = search_xml('syslogserver_arp')
                cvssMetrics = str(cvss_score(items[5]))
                syslog.server_arp = {
                "must_report": True,
                "fixImpact": (items[0]),
                "definition": (items[1]),
                "threatInfo": (items[2]),
                "howtofix": (items[4]),
                "cvss": (cvssMetrics)}
        else:
            syslog.server_arp['must_report'] = False

    toBeReturned = ''
    if syslog.server['must_report'] == True:
        toBeReturned = syslog.server['definition'] + '\n' + syslog.server['threatInfo'] + '\n\n' + syslog.server['howtofix'] + '\n'
    if syslog.level_trap['must_report'] == True:
        toBeReturned = toBeReturned + syslog.level_trap['definition'] + '\n' + syslog.level_trap['threatInfo'] + '\n\n' + syslog.level_trap['howtofix'] + '\n'
    if syslog.level_buffered['must_report'] == True:
        toBeReturned = toBeReturned + syslog.level_buffered['definition'] + '\n' + syslog.level_buffered['threatInfo'] + '\n\n' + syslog.level_buffered['howtofix'] + '\n'
    if syslog.logging_console['must_report'] == True:
        toBeReturned = toBeReturned + syslog.logging_console['definition'] + '\n' + syslog.logging_console['threatInfo'] + '\n\n' + syslog.logging_console['howtofix'] + '\n'
    if syslog.logging_monitor['must_report'] == True:
        toBeReturned = toBeReturned + syslog.logging_monitor['definition'] + '\n' + syslog.logging_monitor['threatInfo'] + '\n\n' + syslog.logging_monitor['howtofix'] + '\n'
    if syslog.logging_buffered['must_report'] == True:
        toBeReturned = toBeReturned + syslog.logging_buffered['definition'] + '\n' + syslog.logging_buffered['threatInfo'] + '\n\n' + syslog.logging_buffered['howtofix'] + '\n'
    if syslog.interface['must_report'] == True:
        toBeReturned = toBeReturned + syslog.interface['definition'] + '\n' + syslog.interface['threatInfo'] + '\n\n' + syslog.interface['howtofix'] + '\n'
    if syslog.timestamp['must_report'] == True:
        toBeReturned = toBeReturned + syslog.timestamp['definition'] + '\n' + syslog.timestamp['threatInfo'] + '\n\n' + syslog.timestamp['howtofix'] + '\n'
    if syslog.server_arp['must_report'] == True:
        toBeReturned = toBeReturned + syslog.server_arp['definition'] + '\n' + syslog.server_arp['threatInfo'] + '\n\n' + syslog.server_arp['howtofix'] + '\n'

    return toBeReturned


def engine_archive(lines, archive):
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
        archive.secure_boot['cmdInCfg'] = search_string(lines, 'secure boot-image')
    except AttributeError:
        pass
    if archive.secure_boot['cmdInCfg'] is not None:
        # feature already configured
        archive.secure_boot['must_report'] = False
    else:
        items = search_xml('archiveSecureImage')
        if __builtin__.iosVersion >= 12.38:
            cvssMetrics = str(cvss_score(items[5]))
            archive.secure_boot = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.38 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            archive.secure_boot = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    try:
        archive.secure_config['cmdInCfg'] = search_string(lines, 'secure boot-config')
    except AttributeError:
        pass
    if archive.secure_config['cmdInCfg'] is not None:
        # feature already configured
        archive.secure_config['must_report'] = False
    else:
        items = search_xml('archivesecure_config')
        if __builtin__.iosVersion >= 12.38:
            cvssMetrics = str(cvss_score(items[5]))
            archive.secure_config = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.38 to get the feature
            cvssMetrics = str(cvss_score(items[5]))
            archive.secure_config = {
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
    if archive.secure_boot['must_report'] == True:
        toBeReturned = toBeReturned + archive.secure_boot['definition'] + '\n' + archive.secure_boot['threatInfo'] + '\n\n' + archive.secure_boot['howtofix'] + '\n'
    if archive.secure_config['must_report'] == True:
        toBeReturned = toBeReturned + archive.secure_config['definition'] + '\n' + archive.secure_config['threatInfo'] + '\n\n' + archive.secure_config['howtofix'] + '\n'
    if archive.logs['must_report'] == True:
        toBeReturned = toBeReturned + archive.logs['definition'] + '\n' + archive.logs['threatInfo'] + '\n\n' + archive.logs['howtofix'] + '\n'

    return toBeReturned

def engine_icmp_redirects(icmpRedirects, fullConfig, ifaceCfg):
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


def engine_icmp_unreach(icmpUnreachable, fullConfig, ifaceCfg):
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

def engine_arp_proxy(proxyArp, fullConfig, ifaceCfg):
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

def engine_ntp(lines, ntp):
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

def engine_ip_options(lines, ipoptions):
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

def engine_ip_src_route(lines, ipsrcroute):
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

def engine_icmp_deny(lines, denyicmp):
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

def engine_ipfrags(lines, ipfrags):
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

def engine_urpf(lines, urpf, ifaceCfg):
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

def engine_urpfv6(lines, urpfv6, ifaceCfg):
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

def engine_ipv6(lines, ipv6, aclIPv6, ifaceCfg):
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

def engine_ipsec(lines, ipsec):
    """IPSec configuration assessment: call admission."""

    try:
        ipsec.cac_ike['cmdInCfg'] = search_re_string(lines, '^crypto call admission limit ike sa .*$')
    except AttributeError:
        pass
    try:
        ipsec.cac_rsc['cmdInCfg'] = search_re_string(lines, '^call admission limit .*$')
    except AttributeError:
        pass

    if ipsec.cac_ike['cmdInCfg'] is None:
            ipsec.cac_ike['must_report'] = True

    if ipsec.cac_rsc['cmdInCfg'] is None:
        ipsec.cac_rsc['must_report'] = True

    if ipsec.cac_ike['must_report'] == True:
        items = search_xml('IPSECcac_ike')
        cvssMetrics = str(cvss_score(items[5]))
        ipsec.cac_ike = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    if ipsec.cac_rsc['must_report'] == True:
        items = search_xml('IPSECcac_rsc')
        cvssMetrics = str(cvss_score(items[5]))
        ipsec.cac_rsc = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if ipsec.cac_ike['must_report'] == True:
        toBeReturned = ipsec.cac_ike['definition'] + '\n' + ipsec.cac_ike['threatInfo'] + '\n\n' + ipsec.cac_ike['howtofix'] + '\n'
    if ipsec.cac_rsc['must_report'] == True:
        toBeReturned = toBeReturned + ipsec.cac_rsc['definition'] + '\n' + ipsec.cac_rsc['threatInfo'] + '\n\n' + ipsec.cac_rsc['howtofix'] + '\n'

    return toBeReturned

def engine_tclsh(lines, tclsh):
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


def engine_tcp(lines, tcp):
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

def engine_netflow(lines, netflow, ifaceCfg):
    """Netflow configuration assessment."""

    for j in range(0, len(ifaceCfg)):
        if search_re_string(ifaceCfg[j].configuration, '^ip flow (ingress|egress)$') is not None:
            netflow.v9_security['interfacegress'] = True

    if netflow.v9_security['interfacegress'] == True:
        try:
            netflow.v9_security['fragoffset'] = search_re_string(lines, '^ip flow-capture fragment-offset$')
        except AttributeError:
            pass
        try:
            netflow.v9_security['icmp'] = search_re_string(lines, '^ip flow-capture icmp$')
        except AttributeError:
            pass
        try:
            netflow.v9_security['ipid'] = search_re_string(lines, '^ip flow-capture ip-id$')
        except AttributeError:
            pass
        try:
            netflow.v9_security['macaddr'] = search_re_string(lines, '^ip flow-capture mac-addresses$')
        except AttributeError:
            pass
        try:
            netflow.v9_security['packetlen'] = search_re_string(lines, '^ip flow-capture packet-length$')
        except AttributeError:
            pass
        try:
            netflow.v9_security['ttl'] = search_re_string(lines, '^ip flow-capture ttl$')
        except AttributeError:
            pass
        try:
            netflow.v9_security['vlid'] = search_re_string(lines, '^ip flow-capture vlan-id$')
        except AttributeError:
            pass

    if ( (netflow.v9_security['fragoffset'] is None) or (netflow.v9_security['icmp'] is None) or (netflow.v9_security['ipid'] is None) or (netflow.v9_security['macaddr'] is None) or (netflow.v9_security['packetlen'] is None) or (netflow.v9_security['ttl'] is None) or (netflow.v9_security['vlid'] is None) ):
        netflow.v9_security['must_report'] = True

    if netflow.v9_security['must_report'] == True:
        items = search_xml('netflowV9')
        if __builtin__.iosVersion >= 12.42:
            cvssMetrics = str(cvss_score(items[5]))
            netflow.v9_security = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}
        else:
            # upgrade to >= 12.42 to get the feature (including L3 fragment-offset)
            cvssMetrics = str(cvss_score(items[5]))
            netflow.v9_security = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[4]),
            "cvss": (cvssMetrics)}

    toBeReturned = ''
    if netflow.v9_security['must_report'] == True:
        toBeReturned = netflow.v9_security['definition'] + '\n' + netflow.v9_security['threatInfo'] + '\n\n' + netflow.v9_security['howtofix'] + '\n'

    return toBeReturned

def engine_qos(lines, qos, ifaceCfg):
    """QoS configuration assessment. Not ready."""
    toBeReturned = ''
    return toBeReturned
