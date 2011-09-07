# -*- coding: iso-8859-1 -*-

__docformat__ = 'restructuredtext'
__version__ = '$Id$'

import __builtin__
from routerdefense.common import *

from xml import *

def engine_port_security(lines, portsecurity, ifaceCfg):
    """Port security configuration."""
    for i in range(0, len(ifaceCfg)):
        if search_re_string(ifaceCfg[i].configuration, '^switchport access vlan .*$') is not None:
            if search_re_string(ifaceCfg[i].configuration,'switchport port-security maximum .* vlan access') is None:
                portsecurity.maximum_access['candidates'].append(ifaceCfg[i].name.strip())
                portsecurity.maximum_access['must_report'] = True
        if search_re_string(ifaceCfg[i].configuration, '^switchport voice vlan .*$') is not None:
            if search_re_string(ifaceCfg[i].configuration,'switchport port-security maximum .* vlan voice') is None:
                portsecurity.maximum_voice['candidates'].append(ifaceCfg[i].name.strip())
                portsecurity.maximum_voice['must_report'] = True
        for line in ifaceCfg[i].configuration:
            if line.find('switchport mode access') != -1:
                break
            if line.find('switchport port-security violation') == -1:
                if not ifaceCfg[i].name.strip() in portsecurity.violation['candidates']:
                    if not 'Vlan' or not 'Loopback' in ifaceCfg[i].name.strip():
                        portsecurity.violation['candidates'].append(ifaceCfg[i].name.strip())
                        portsecurity.violation['must_report'] = True
            if line.find('switchport port-security mac-address sticky') == -1:
                if not ifaceCfg[i].name.strip() in portsecurity.sticky['candidates']:
                    if not 'Vlan' or not 'Loopback' in ifaceCfg[i].name.strip():
                        portsecurity.sticky['candidates'].append(ifaceCfg[i].name.strip())
                        portsecurity.sticky['must_report'] = True
            if re.search('^switchport port-security maximum .*$', line) is None:
                if not ifaceCfg[i].name.strip() in portsecurity.maximum_total['candidates']:
                    if not 'Vlan' or not 'Loopback' in ifaceCfg[i].name.strip():
                        portsecurity.maximum_total['candidates'].append(ifaceCfg[i].name.strip())
                        portsecurity.maximum_total['must_report'] = True


    if portsecurity.violation['must_report'] == True:
        items = search_xml('portsecurityViolation')
        cvssMetrics = str(cvss_score(items[5]))
        portsecurity.violation = {
        "candidates": portsecurity.violation['candidates'],
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3].strip().replace('[%interface]', ", ".join(portsecurity.violation['candidates']), 1)),
        "cvss": (cvssMetrics)}

    if portsecurity.sticky['must_report'] == True:
        items = search_xml('portsecuritySticky')
        cvssMetrics = str(cvss_score(items[5]))
        portsecurity.sticky = {
        "candidates": portsecurity.sticky['candidates'],
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3].strip().replace('[%interface]', ", ".join(portsecurity.violation['candidates']), 1)),
        "cvss": (cvssMetrics)}

    if portsecurity.maximum_total['must_report'] == True:
        items = search_xml('portsecuritymaximum_total')
        cvssMetrics = str(cvss_score(items[5]))
        portsecurity.maximum_total = {
        "candidates": portsecurity.maximum_total['candidates'],
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3].strip().replace('[%interface]', ", ".join(portsecurity.violation['candidates']), 1)),
        "cvss": (cvssMetrics)}

    if portsecurity.maximum_access['must_report'] == True:
        items = search_xml('portsecuritymaximum_access')
        cvssMetrics = str(cvss_score(items[5]))
        portsecurity.maximum_access = {
        "candidates": portsecurity.maximum_access['candidates'],
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3].strip().replace('[%interface]', ", ".join(portsecurity.violation['candidates']), 1)),
        "cvss": (cvssMetrics)}

    if portsecurity.maximum_voice['must_report'] == True:
        items = search_xml('portsecuritymaximum_voice')
        cvssMetrics = str(cvss_score(items[5]))
        portsecurity.maximum_voice = {
        "candidates": portsecurity.maximum_voice['candidates'],
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3].strip().replace('[%interface]', ", ".join(portsecurity.violation['candidates']), 1)),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if portsecurity.sticky['must_report'] == True:
        toBeReturned = portsecurity.sticky['definition'] + '\n' + portsecurity.sticky['threatInfo'] + '\n\n' + portsecurity.sticky['howtofix'] + '\n'
    if portsecurity.violation['must_report'] == True:
        toBeReturned = toBeReturned + portsecurity.violation['definition'] + '\n' + portsecurity.violation['threatInfo'] + '\n\n' + portsecurity.violation['howtofix'] + '\n'
    if portsecurity.maximum_total['must_report'] == True:
        toBeReturned = toBeReturned + portsecurity.maximum_total['definition'] + '\n' + portsecurity.maximum_total['threatInfo'] + '\n\n' + portsecurity.maximum_total['howtofix'] + '\n'
    if portsecurity.maximum_access['must_report'] == True:
        toBeReturned = toBeReturned + portsecurity.maximum_access['definition'] + '\n' + portsecurity.maximum_access['threatInfo'] + '\n\n' + portsecurity.maximum_access['howtofix'] + '\n'
    if portsecurity.maximum_voice['must_report'] == True:
        toBeReturned = toBeReturned + portsecurity.maximum_voice['definition'] + '\n' + portsecurity.maximum_voice['threatInfo'] + '\n\n' + portsecurity.maximum_voice['howtofix'] + '\n'

    return toBeReturned

def engine_layer2(lines, level2protocols, ifaceCfg):
    """Level 2 protocols configuration assessment: spanning-tree, dot1x, flow-control, unused ports, UDLD."""

    #if search_re_string(lines,'^vtp domain .*$') is not None:
        #if search_re_string(lines,'^vtp password .*$') is None and search_re_string(lines,'^vtp mode transparent$') is not None:
            #level2protocols.vtp_secure['must_report'] = True

    if __builtin__.deviceType != 'router' and search_re_string(lines,'^spanning-tree portfast bpdu_guard default$') is None:
            level2protocols.bpdu_guard['must_report'] = True

    if __builtin__.deviceType == 'switch' and search_re_string(lines,'^dot1x system-auth-control$') is None:
        level2protocols.dot1x['must_report'] = True

    for i in range(0, len(ifaceCfg)):
        if search_re_string(ifaceCfg[i].configuration, '^switchport mode (access|trunk)$') is not None:
            if search_re_string(ifaceCfg[i].configuration,'^switchport nonegotiate$') is None:
                level2protocols.nonegotiate['candidates'].append(ifaceCfg[i].name.strip())
                level2protocols.nonegotiate['must_report'] = True
            elif search_re_string(ifaceCfg[i].configuration,'^switchport access vlan 1$') is not None:
                level2protocols.vlan_1['candidates'].append(ifaceCfg[i].name.strip())
                level2protocols.vlan_1['must_report'] = True

        if search_re_string(ifaceCfg[i].configuration, '^flowcontrol receive off$') is None:
            if not 'Loopback' in ifaceCfg[i].name.strip() and not 'Vlan' in ifaceCfg[i].name.strip():
                level2protocols.flowcontrol['candidates'].append(ifaceCfg[i].name.strip())
                level2protocols.flowcontrol['must_report'] = True

        if search_re_string(ifaceCfg[i].configuration, '^shutdown$') is not None:
            if search_re_string(ifaceCfg[i].configuration,'^switchport access vlan 999$') is None:
                if __builtin__.deviceType == 'switch':
                    level2protocols.unused_ports['candidates'].append(ifaceCfg[i].name.strip())
                    level2protocols.unused_ports['must_report'] = True

    try:
        level2protocols.udld['cmdInCfg'] = search_string(lines, 'no udld enable')
    except AttributeError:
        pass

    if level2protocols.udld['cmdInCfg'] is None:
        level2protocols.udld['must_report'] = True

    if level2protocols.nonegotiate['must_report'] == True:
        items = search_xml('nonegotiate')
        cvssMetrics = str(cvss_score(items[5]))
        level2protocols.nonegotiate = {
        "candidates": level2protocols.nonegotiate['candidates'],
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    if level2protocols.flowcontrol['must_report'] == True:
        items = search_xml('flowcontrol')
        cvssMetrics = str(cvss_score(items[5]))
        level2protocols.flowcontrol = {
        "candidates": level2protocols.flowcontrol['candidates'],
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    if level2protocols.udld['must_report'] == True:
        items = search_xml('udld')
        cvssMetrics = str(cvss_score(items[5]))
        level2protocols.udld = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    if level2protocols.vlan_1['must_report'] == True:
        items = search_xml('vlan_1')
        cvssMetrics = str(cvss_score(items[5]))
        level2protocols.vlan_1 = {
        "candidates": level2protocols.vlan_1['candidates'],
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    if (level2protocols.unused_ports['must_report'] == True):
        items = search_xml('unused_ports')
        cvssMetrics = str(cvss_score(items[5]))
        level2protocols.unused_ports = {
        "candidates": level2protocols.unused_ports['candidates'],
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    """
    if level2protocols.vtp_secure['must_report'] == True:
        items = search_xml('vtp_secure')
        cvssMetrics = str(cvss_score(items[5]))
        level2protocols.vtp_secure = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}
    """
    if level2protocols.bpdu_guard['must_report'] == True:
        items = search_xml('bpdu_guard')
        cvssMetrics = str(cvss_score(items[5]))
        level2protocols.bpdu_guard = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    if level2protocols.stp_root['must_report'] == True:
        items = search_xml('stp_root')
        cvssMetrics = str(cvss_score(items[5]))
        level2protocols.stp_root = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    if level2protocols.dot1x['must_report'] == True:
        items = search_xml('dot1x')
        cvssMetrics = str(cvss_score(items[5]))
        level2protocols.dot1x = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if level2protocols.nonegotiate['must_report'] == True:
        toBeReturned = level2protocols.nonegotiate['definition'] + '\n' + level2protocols.nonegotiate['threatInfo'] + '\n\n' + level2protocols.nonegotiate['howtofix'] + '\n'
    if level2protocols.flowcontrol['must_report'] == True:
        toBeReturned = toBeReturned + level2protocols.flowcontrol['definition'] + '\n' + level2protocols.flowcontrol['threatInfo'] + '\n\n' + level2protocols.flowcontrol['howtofix'] + '\n'
    if level2protocols.udld['must_report'] == True:
        toBeReturned = toBeReturned + level2protocols.udld['definition'] + '\n' + level2protocols.udld['threatInfo'] + '\n\n' + level2protocols.udld['howtofix'] + '\n'
    if level2protocols.vlan_1['must_report'] == True:
        toBeReturned = toBeReturned + level2protocols.vlan_1['definition'] + '\n' + level2protocols.vlan_1['threatInfo'] + '\n\n' + level2protocols.vlan_1['howtofix'] + '\n'
    if level2protocols.unused_ports['must_report'] == True:
        toBeReturned = toBeReturned + level2protocols.unused_ports['definition'] + '\n' + level2protocols.unused_ports['threatInfo'] + '\n\n' + level2protocols.unused_ports['howtofix'] + '\n'
    if level2protocols.vtp_secure['must_report'] == True:
        toBeReturned = toBeReturned + level2protocols.vtp_secure['definition'] + '\n' + level2protocols.vtp_secure['threatInfo'] + '\n\n' + level2protocols.vtp_secure['howtofix'] + '\n'
    if level2protocols.bpdu_guard['must_report'] == True:
        toBeReturned = toBeReturned + level2protocols.bpdu_guard['definition'] + '\n' + level2protocols.bpdu_guard['threatInfo'] + '\n\n' + level2protocols.bpdu_guard['howtofix'] + '\n'
    if level2protocols.stp_root['must_report'] == True:
        toBeReturned = toBeReturned + level2protocols.stp_root['definition'] + '\n' + level2protocols.stp_root['threatInfo'] + '\n\n' + level2protocols.stp_root['howtofix'] + '\n'
    if level2protocols.dot1x['must_report'] == True:
        toBeReturned = toBeReturned + level2protocols.dot1x['definition'] + '\n' + level2protocols.dot1x['threatInfo'] + '\n\n' + level2protocols.dot1x['howtofix'] + '\n'

    return toBeReturned

def engine_cdp(cdpConfiguration, fullConfig, ifaceCfg):
    """CDP services assessment."""
    globalCdpFound = False
    noCdpEnableFound = False
    for line in fullConfig:
        if line == 'cdp run':
            globalCdpFound = True
        elif line == 'no cdp run':
            globalCdpFound = False
    cdpConfiguration.cdp['globalCdp'] = globalCdpFound

    for i in range(0, len(ifaceCfg)):
        for line in ifaceCfg[i].configuration:
            if line == 'no cdp enable':
                if not 'Loopback' in ifaceCfg[i].name.strip() and not 'Vlan' in ifaceCfg[i].name.strip():
                    cdpConfiguration.cdp['disabledIfsCdp'].append(ifaceCfg[i].name.strip())
                    noCdpEnableFound = True
        if noCdpEnableFound == False:
            if not 'Loopback' in ifaceCfg[i].name.strip() and not 'Vlan' in ifaceCfg[i].name.strip():
                cdpConfiguration.cdp['enabledIfsCdp'].append(ifaceCfg[i].name.strip())

    if ( (cdpConfiguration.cdp['globalCdp'] == True) or (cdpConfiguration.cdp['enabledIfsCdp']) ):
        items = search_xml('serviceCDP')
        cvssMetrics = str(cvss_score(items[5]))
        cdpConfiguration.cdp['must_report'] = True
        cdpConfiguration.cdp['fixImpact'] = items[0]
        cdpConfiguration.cdp['definition'] = items[1]
        cdpConfiguration.cdp['threatInfo'] = items[2]
        cdpConfiguration.cdp['howtofix'] = items[3]
        cdpConfiguration.cdp['howtofix'] = cdpConfiguration.cdp['howtofix'].strip().replace('[%CdpifsEnabled]', ", ".join(cdpConfiguration.cdp['enabledIfsCdp']), 1)
        cdpConfiguration.cdp['howtofix'] = cdpConfiguration.cdp['howtofix'].strip().replace('[%CdpifsDisabled]', ", ".join(cdpConfiguration.cdp['disabledIfsCdp']), 1)
        cdpConfiguration.cdp['cvss'] = cvssMetrics

        return cdpConfiguration.cdp['definition'] + '\n' + cdpConfiguration.cdp['threatInfo'] + '\n\n' + cdpConfiguration.cdp['howtofix'] + '\n'

def engine_lldp(lldpConfiguration, fullConfig, ifaceCfg):
    """LLDP services assessment."""
    globalLldpFound = True
    for line in fullConfig:
        if line == 'lldp run global' or line == 'lldp run':
            globalLldpFound = True
        elif line == 'no lldp run global' or line == 'no lldp run':
            globalLldpFound = False
    lldpConfiguration.lldp['globalLldp'] = globalLldpFound
    for i in range(0, len(ifaceCfg)):
        lldpTransmit = True
        lldpReceive = True
        for line in ifaceCfg[i].configuration:
            if line == 'no lldp transmit':
                lldpTransmit = False
            if line == 'no lldp receive':
                lldpReceive = False
        if lldpTransmit == True:
            if not 'Loopback' in ifaceCfg[i].name.strip() and not 'Vlan' in ifaceCfg[i].name.strip():
                lldpConfiguration.lldp['enabledTransmitLldp'].append(ifaceCfg[i].name.strip())
        if lldpReceive == True:
            if not 'Loopback' in ifaceCfg[i].name.strip() and not 'Vlan' in ifaceCfg[i].name.strip():
                lldpConfiguration.lldp['enabledReceiveLldp'].append(ifaceCfg[i].name.strip())
        if lldpTransmit == False and lldpReceive == False:
            if not 'Loopback' in ifaceCfg[i].name.strip() and not 'Vlan' in ifaceCfg[i].name.strip():
                lldpConfiguration.lldp['disabledIfsLldp'].append(ifaceCfg[i].name.strip())

    ToBeReturned = 'LLDP is OK.'
    if ( (lldpConfiguration.lldp['globalLldp'] == True) or (lldpConfiguration.lldp['enabledTransmitLldp']) or (lldpConfiguration.lldp['enabledReceiveLldp']) ):
        if __builtin__.iosVersion >= 12.237:
            items = search_xml('serviceLLDP')
            cvssMetrics = str(cvss_score(items[5]))
            lldpConfiguration.lldp['must_report'] = True
            lldpConfiguration.lldp['fixImpact'] = items[0]
            lldpConfiguration.lldp['definition'] = items[1]
            lldpConfiguration.lldp['threatInfo'] = items[2]
            lldpConfiguration.lldp['howtofix'] = items[3]

            if lldpConfiguration.lldp['enabledTransmitLldp']:
                lldpConfiguration.lldp['howtofix'] = lldpConfiguration.lldp['howtofix'].strip().replace('[%LldpEnabledTx]', ", ".join(lldpConfiguration.lldp['enabledTransmitLldp']), 1)
            else:
                lldpConfiguration.lldp['howtofix'] = lldpConfiguration.lldp['howtofix'].strip().replace('[%LldpEnabledTx]', "None", 1)
            if lldpConfiguration.lldp['enabledReceiveLldp']:
                lldpConfiguration.lldp['howtofix'] = lldpConfiguration.lldp['howtofix'].strip().replace('[%LldpEnabledRx]', ", ".join(lldpConfiguration.lldp['enabledReceiveLldp']), 1)
            else:
                lldpConfiguration.lldp['howtofix'] = lldpConfiguration.lldp['howtofix'].strip().replace('[%LldpEnabledRx]', "None", 1)
            if lldpConfiguration.lldp['disabledIfsLldp']:
                lldpConfiguration.lldp['howtofix'] = lldpConfiguration.lldp['howtofix'].strip().replace('[%LldpifsDisabled]', ", ".join(lldpConfiguration.lldp['disabledIfsLldp']), 1)
            else:
                lldpConfiguration.lldp['howtofix'] = lldpConfiguration.lldp['howtofix'].strip().replace('[%LldpifsDisabled]', "None", 1)

            lldpConfiguration.lldp['cvss'] = cvssMetrics

            ToBeReturned = lldpConfiguration.lldp['definition'] + '\n' + lldpConfiguration.lldp['threatInfo'] + '\n\n' + lldpConfiguration.lldp['howtofix'] + '\n'
            return ToBeReturned
        elif __builtin__.iosVersion is None:
            items = search_xml('serviceLLDP')
            cvssMetrics = str(cvss_score(items[5]))
            lldpConfiguration.lldp['must_report'] = True
            lldpConfiguration.lldp['fixImpact'] = items[0]
            lldpConfiguration.lldp['definition'] = items[1]
            lldpConfiguration.lldp['threatInfo'] = items[2]
            lldpConfiguration.lldp['howtofix'] = items[3]

            if lldpConfiguration.lldp['enabledTransmitLldp']:
                lldpConfiguration.lldp['howtofix'] = lldpConfiguration.lldp['howtofix'].strip().replace('[%LldpEnabledTx]', ", ".join(lldpConfiguration.lldp['enabledTransmitLldp']), 1)
            else:
                lldpConfiguration.lldp['howtofix'] = lldpConfiguration.lldp['howtofix'].strip().replace('[%LldpEnabledTx]', "None", 1)
            if lldpConfiguration.lldp['enabledReceiveLldp']:
                lldpConfiguration.lldp['howtofix'] = lldpConfiguration.lldp['howtofix'].strip().replace('[%LldpEnabledRx]', ", ".join(lldpConfiguration.lldp['enabledReceiveLldp']), 1)
            else:
                lldpConfiguration.lldp['howtofix'] = lldpConfiguration.lldp['howtofix'].strip().replace('[%LldpEnabledRx]', "None", 1)
            if lldpConfiguration.lldp['disabledIfsLldp']:
                lldpConfiguration.lldp['howtofix'] = lldpConfiguration.lldp['howtofix'].strip().replace('[%LldpifsDisabled]', ", ".join(lldpConfiguration.lldp['disabledIfsLldp']), 1)
            else:
                lldpConfiguration.lldp['howtofix'] = lldpConfiguration.lldp['howtofix'].strip().replace('[%LldpifsDisabled]', "None", 1)

            lldpConfiguration.lldp['cvss'] = cvssMetrics

            ToBeReturned = lldpConfiguration.lldp['definition'] + '\n' + lldpConfiguration.lldp['threatInfo'] + '\n\n' + lldpConfiguration.lldp['howtofix'] + '\n'
            return ToBeReturned
    else:
        return ToBeReturned

