# -*- coding: iso-8859-1 -*-

__docformat__ = 'restructuredtext'
__version__ = '$Id$'

import __builtin__
from routerdefense.common import *

from xml import *

def engine_bgp(lines, bgp, aclIPv4):
    """BGP configuration assessment."""

    if search_string(lines, 'router bgp') is None:
        return

    remoteAsCount = 0
    ttl_securityCount = 0
    session_passwordCount = 0
    max_prefixesCount = 0
    prefix_listInCount = 0
    prefix_listOutCount = 0
    aspath_listInCount = 0
    aspath_listOutCount = 0
    maxaspathLimit = 0

    remoteAsCount = search_re_string_count(lines, 'neighbor .* remote-as .*')
    ttl_securityCount = search_re_string_count(lines, 'neighbor .* ttl-security hops .*')
    session_passwordCount = search_re_string_count(lines, 'neighbor .* password .*')
    max_prefixesCount = search_re_string_count(lines, 'neighbor .* maximum-prefix .*')
    prefix_listInCount = search_re_string_count(lines, 'neighbor .* prefix-list .* in')
    prefix_listOutCount = search_re_string_count(lines, 'neighbor .* prefix-list .* out')
    aspath_listInCount = search_re_string_count(lines, 'neighbor .* filter-list .* in')
    aspath_listOutCount = search_re_string_count(lines, 'neighbor .* filter-list .* out')
    maxaspathLimit = search_re_string_count(lines, '^bgp maxas-limit .*$')

    if ttl_securityCount < remoteAsCount:
        bgp.ttl_security['must_report'] = True

    if session_passwordCount < remoteAsCount:
        bgp.session_password['must_report'] = True

    if max_prefixesCount < remoteAsCount:
        bgp.max_prefixes['must_report'] = True

    if prefix_listInCount < remoteAsCount:
        bgp.prefix_list['must_report'] = True

    if prefix_listOutCount < remoteAsCount:
        bgp.prefix_list['must_report'] = True

    if aspath_listInCount < remoteAsCount:
        bgp.aspath_list['must_report'] = True

    if aspath_listOutCount < remoteAsCount:
        bgp.aspath_list['must_report'] = True

    if maxaspathLimit <= 0:
        bgp.maxpath_limit['must_report'] = True

    if bgp.ttl_security['must_report'] == True:
        items = search_xml('bgpttl_security')
        cvssMetrics = str(cvss_score(items[5]))
        bgp.ttl_security = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    if bgp.session_password['must_report'] == True:
        items = search_xml('bgpsession_password')
        cvssMetrics = str(cvss_score(items[5]))
        bgp.session_password = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    if bgp.max_prefixes['must_report'] == True:
        items = search_xml('bgpmax_prefixes')
        cvssMetrics = str(cvss_score(items[5]))
        bgp.max_prefixes = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    if bgp.prefix_list['must_report'] == True:
        items = search_xml('bgpprefix_list')
        cvssMetrics = str(cvss_score(items[5]))
        bgp.prefix_list = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    if bgp.aspath_list['must_report'] == True:
        items = search_xml('bgpaspath_list')
        cvssMetrics = str(cvss_score(items[5]))
        bgp.aspath_list = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    if bgp.maxpath_limit['must_report'] == True:
        items = search_xml('bgpMaxASlimit')
        cvssMetrics = str(cvss_score(items[5]))
        bgp.maxpath_limit = {
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if bgp.ttl_security['must_report'] == True:
        toBeReturned = bgp.ttl_security['definition'] + '\n'+ bgp.ttl_security['threatInfo'] + '\n\n' + bgp.ttl_security['howtofix'] + '\n'
    if bgp.session_password['must_report'] == True:
        toBeReturned = toBeReturned + bgp.session_password['definition'] + '\n' + bgp.session_password['threatInfo'] + '\n\n' + bgp.session_password['howtofix'] + '\n'
    if bgp.max_prefixes['must_report'] == True:
        toBeReturned = toBeReturned + bgp.max_prefixes['definition'] + '\n' + bgp.max_prefixes['threatInfo'] + '\n\n' + bgp.max_prefixes['howtofix'] + '\n'
    if bgp.prefix_list['must_report'] == True:
        toBeReturned = toBeReturned + bgp.prefix_list['definition'] + '\n' + bgp.prefix_list['threatInfo'] + '\n\n' + bgp.prefix_list['howtofix'] + '\n'
    if bgp.aspath_list['must_report'] == True:
        toBeReturned = toBeReturned + bgp.aspath_list['definition'] + '\n' + bgp.aspath_list['threatInfo'] + '\n\n' + bgp.aspath_list['howtofix'] + '\n'
    if bgp.maxpath_limit['must_report'] == True:
        toBeReturned = toBeReturned + bgp.maxpath_limit['definition'] + '\n' + bgp.maxpath_limit['threatInfo'] + '\n\n' + bgp.maxpath_limit['howtofix'] + '\n'

    return toBeReturned

def engine_eigrp(lines, eigrp, ifaceCfg):
    """EIGRP configuration assessment."""

    if search_string(lines, 'router eigrp') is None:
        return
    auth_md5 = None
    eigrpInstances = 0
    eigrpInstances = search_string_count(lines, 'router eigrp')
    if eigrpInstances != 0:
        for i,v in enumerate(lines):
            if v.rfind('router eigrp') != -1:
                eigrp.asNumber.append(v.split(' ')[2])
                eigrpLines= []
                lineEigrpLocation = i
                eigrpLines.append(stripping(lines[i]))
                for j in range(lineEigrpLocation + 1, len(lines)):
                    if lines[j].startswith(" ") or not lines[j].startswith("!"):
                        eigrpLines.append(stripping(lines[j]))
                    else:
                        break
                    try:
                        eigrp.passive['cmdInCfg'] = search_string(eigrpLines, 'passive-interface default')
                    except AttributeError:
                        pass
                    try:
                        eigrp.rfilter_in['cmdInCfg'] = search_re_string(eigrpLines, 'distribute-list prefix .* in .*')
                    except AttributeError:
                        pass
                    try:
                        eigrp.rfilter_out['cmdInCfg'] = search_re_string(eigrpLines, 'distribute-list prefix .* out .*')
                    except AttributeError:
                        pass

                for line in eigrpLines:
                    if line.find('no passive-interface') != -1:
                        eigrp.activeIfaces.append(line.split(' ')[2])

                if ( (eigrp.passive['cmdInCfg'] is None) ):
                        eigrp.passive['asn'].append(v.split(' ')[2].strip())
                        eigrp.passive['must_report'] = True

                if ( (eigrp.rfilter_in['cmdInCfg'] is None) ):
                    eigrp.rfilter_in['asn'].append(v.split(' ')[2].strip())
                    eigrp.rfilter_in['must_report'] = True

                if ( (eigrp.rfilter_out['cmdInCfg'] is None) ):
                    eigrp.rfilter_out['asn'].append(v.split(' ')[2].strip())
                    eigrp.rfilter_out['must_report'] = True

                for ifaceName in eigrp.activeIfaces:
                    for index in range(0, len(ifaceCfg)):
                        if ifaceCfg[index].name.strip() == ifaceName.strip():
                            auth_md5 = search_re_string(ifaceCfg[index].configuration, 'ip authentication mode eigrp .* md5')
                            if auth_md5 is None:
                                eigrp.auth_md5['interfaces'].append(ifaceName.strip())
                                eigrp.auth_md5['asn'].append(v.split(' ')[2].strip())
                                eigrp.auth_md5['must_report'] = True

                if eigrp.passive['must_report'] == True:
                    items = search_xml('eigrpPassiveDefault')
                    cvssMetrics = str(cvss_score(items[5]))
                    eigrp.passive = {
                    "must_report": True,
                    "asn": eigrp.passive['asn'],
                    "fixImpact": (items[0]),
                    "definition": (items[1]),
                    "threatInfo": (items[2]),
                    "howtofix": (items[3]),
                    "cvss": (cvssMetrics)}

                if eigrp.auth_md5['must_report'] == True:
                    items = search_xml('eigrpAuthModeMD5')
                    cvssMetrics = str(cvss_score(items[5]))
                    eigrp.auth_md5 = {
                    "must_report": True,
                    "interfaces": eigrp.auth_md5['interfaces'],
                    "asn": eigrp.auth_md5['asn'],
                    "fixImpact": (items[0]),
                    "definition": (items[1]),
                    "threatInfo": (items[2]),
                    "howtofix": (items[3]),
                    "cvss": (cvssMetrics)}

                if eigrp.rfilter_in['must_report'] == True:
                    items = search_xml('eigrpRouteFilteringIn')
                    cvssMetrics = str(cvss_score(items[5]))
                    eigrp.rfilter_in = {
                    "must_report": True,
                    "asn": eigrp.rfilter_in['asn'],
                    "fixImpact": (items[0]),
                    "definition": (items[1]),
                    "threatInfo": (items[2]),
                    "howtofix": (items[3]),
                    "cvss": (cvssMetrics)}

                if eigrp.rfilter_out['must_report'] == True:
                    items = search_xml('eigrpRouteFilteringOut')
                    cvssMetrics = str(cvss_score(items[5]))
                    eigrp.rfilter_out = {
                    "must_report": True,
                    "asn": eigrp.rfilter_out['asn'],
                    "fixImpact": (items[0]),
                    "definition": (items[1]),
                    "threatInfo": (items[2]),
                    "howtofix": (items[3]),
                    "cvss": (cvssMetrics)}

    toBeReturned = ''
    if eigrp.passive['must_report'] == True:
        toBeReturned = eigrp.passive['definition'] + '\n' + eigrp.passive['threatInfo'] + '\n\n' + eigrp.passive['howtofix'] + '\n'
    if eigrp.auth_md5['must_report'] == True:
        toBeReturned = toBeReturned + eigrp.auth_md5['definition'] + '\n' + eigrp.auth_md5['threatInfo'] + '\n\n' + eigrp.auth_md5['howtofix'] + '\n'
    if eigrp.rfilter_in['must_report'] == True:
        toBeReturned = toBeReturned + eigrp.rfilter_in['definition'] + '\n' + eigrp.rfilter_in['threatInfo'] + '\n\n' + eigrp.rfilter_in['howtofix'] + '\n'
    if eigrp.rfilter_out['must_report'] == True:
        toBeReturned = toBeReturned + eigrp.rfilter_out['definition'] + '\n' + eigrp.rfilter_out['threatInfo'] + '\n\n' + eigrp.rfilter_out['howtofix'] + '\n'

    return toBeReturned

def engine_rip(lines, rip, ifaceCfg):
    """RIP configuration assessment."""

    if search_string(lines, 'router rip') is None:
        return
    rip.version = 1
    for i,v in enumerate(lines):
        if v.rfind('router rip') != -1:
            ripLines= []
            lineRipLocation = i
            ripLines.append(stripping(lines[i]))
            for j in range(lineRipLocation + 1, len(lines)):
                if lines[j].startswith(" ") or not lines[j].startswith("!"):
                    ripLines.append(stripping(lines[j]))
                else:
                    break

    for line in ripLines:
        if line.find('version 2') != -1:
            rip.version = 2

    ripMask = None
    ripMask = search_re_string(ripLines, 'network .* .*')
    if ripMask is not None:
        rip.version = 2

    if rip.version == 1:
        return
    elif rip.version == 2:
        ripMD5 = None
        MD5notFound = False
        for line in ripLines:
            if MD5notFound == False:
                if line.find('network',0, 8) != -1:
                    ripNet =line.split(' ')[1]
                    ifIPmask = None
                    for index in range(0, len(ifaceCfg)):
                        ifIPmask = search_re_string(ifaceCfg[index].configuration, 'ip address .* .*')
                        if ifIPmask is not None:
                            ipTuple = ifIPmask.split(' ')
                            ipAddress = ipTuple[2]
                            Mask = ipTuple[3]
                            if ripNet == network_address(ipAddress, Mask):
                                ripMD5 = search_string(ifaceCfg[index].configuration, 'ip rip authentication mode md5')
                                if ripMD5 is None:
                                    MD5notFound = True
                                    rip.auth_md5['interfaces'].append(ifaceCfg[index].name.strip())
                                    rip.auth_md5['must_report'] = True

    if rip.auth_md5['must_report'] == True:
        items = search_xml('ripAuthModeMD5')
        cvssMetrics = str(cvss_score(items[5]))
        rip.auth_md5 = {
        "must_report": True,
        "interfaces": rip.auth_md5['interfaces'],
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if rip.auth_md5['must_report'] == True:
        toBeReturned = rip.auth_md5['definition'] + '\n' + rip.auth_md5['threatInfo'] + '\n\n' + rip.auth_md5['howtofix'] + '\n'

    return toBeReturned


def engine_ospf(lines, ospf, ifaceCfg):
    """"OSPF configuration assessment."""

    if search_string(lines, 'router ospf') is None:
        return
    auth_md5 = None
    ospfInstances = 0
    ospfInstances = search_string_count(lines, 'router ospf')
    if ospfInstances != 0:
        for i,v in enumerate(lines):
            if v.find('router ospf',0,12) != -1:
                ospfLines= []
                lineOspfLocation = i
                ospfLines.append(stripping(lines[i]))
                currentPid = ospfLines[0].split(' ')[2]
                for j in range(lineOspfLocation + 1, len(lines)):
                    if lines[j].startswith(" ") or not lines[j].startswith("!"):
                        ospfLines.append(stripping(lines[j]))
                    else:
                        break
                    try:
                        ospf.passive['cmdInCfg'] = search_string(ospfLines, 'passive-interface default')
                    except AttributeError:
                        pass
                    try:
                        ospf.maxLSA['cmdInCfg'] = search_re_string(ospfLines, 'max-lsa .*')
                    except AttributeError:
                        pass

                if ( (ospf.passive['cmdInCfg'] is None) ):
                    ospf.passive['pid'].append(currentPid)
                    ospf.passive['must_report'] = True

                if ( (ospf.rfilter_in['cmdInCfg'] is None) ):
                    ospf.rfilter_in['pid'].append(currentPid)
                    ospf.rfilter_in['must_report'] = True

                if ( (ospf.rfilter_out['cmdInCfg'] is None) ):
                    ospf.rfilter_out['pid'].append(currentPid)
                    ospf.rfilter_out['must_report'] = True

                if ( (ospf.maxLSA['cmdInCfg'] is None) ):
                    ospf.maxLSA['pid'].append(currentPid)
                    ospf.maxLSA['must_report'] = True

                ospf.area = []
                for line in ospfLines:
                    if line.find('network',0,8) != -1:
                        if not line.split(' ')[4] in ospf.area:
                            ospf.area.append(line.split(' ')[4])

                for areaNumber in ospf.area:
                    areaDigest = False
                    searchArea = None
                    searchArea = search_re_string(ospfLines,'area .* authentication message-digest')
                    if searchArea is not None:
                        matchArea = searchArea.split(' ')[1]
                        if matchArea == areaNumber:
                            areaDigest = True

                    if areaDigest == False:
                        if not areaNumber in ospf.auth_md5['area']:
                            ospf.auth_md5['area'].append(areaNumber)
                        if not currentPid in ospf.auth_md5['pid']:
                            ospf.auth_md5['pid'].append(currentPid)
                        ospf.auth_md5['must_report'] = True

                if ospf.auth_md5['must_report'] == True:
                    for line in ospfLines:
                        if line.find('network',0, 8) != -1:
                            ospfNet =line.split(' ')[1]
                            ifIPmask = None
                            for index in range(0, len(ifaceCfg)):
                                ifIPmask = search_re_string(ifaceCfg[index].configuration, 'ip address .* .*')
                                if ifIPmask is not None:
                                    ipTuple = ifIPmask.split(' ')
                                    ipAddress = ipTuple[2]
                                    Mask = ipTuple[3]
                                    if ospfNet == network_address(ipAddress, Mask):
                                        ospfMD5 = search_re_string(ifaceCfg[index].configuration, 'ip ospf message-digest-key .* md5 .*')
                                        if ospfMD5 is None:
                                            ospf.auth_md5['interfaces'].append(ifaceCfg[index].name.strip())

                    searchFilterAreaIn = 'area ' + str(areaNumber) + ' filter-list prefix .* in'
                    if search_re_string(ospfLines, searchFilterAreaIn) is None:
                        if not areaNumber in ospf.rfilter_in['area']:
                            ospf.rfilter_in['area'].append(areaNumber)

                    searchFilterAreaOut = 'area ' + str(areaNumber) + ' filter-list prefix .* out'
                    if search_re_string(ospfLines, searchFilterAreaOut) is None:
                        if not areaNumber in ospf.rfilter_out['area']:
                            ospf.rfilter_out['area'].append(areaNumber)


    if ospf.passive['must_report'] == True:
        items = search_xml('ospfPassiveDefault')
        cvssMetrics = str(cvss_score(items[5]))
        ospf.passive = {
        "pid": ospf.passive['pid'],
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3]),
        "cvss": (cvssMetrics)}

    if ospf.auth_md5['must_report'] == True:
        items = search_xml('ospfAuthModeMD5')
        cvssMetrics = str(cvss_score(items[5]))
        ospf.auth_md5 = {
        "must_report": True,
        "pid": ospf.auth_md5['pid'],
        "area": ospf.auth_md5['area'],
        "interfaces": ospf.auth_md5['interfaces'],
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3].strip() \
            .replace('[%ospfPID]', "".join(ospf.auth_md5['pid']), 1) \
            .replace('[%ospfArea]', "".join(ospf.auth_md5['area']), 1) \
            .replace('[%ospfinterface]', ", ".join(ospf.auth_md5['interfaces']), 1)),
        "cvss": (cvssMetrics)}

    if ospf.rfilter_in['must_report'] == True:
        items = search_xml('ospfRouteFilteringIn')
        cvssMetrics = str(cvss_score(items[5]))
        ospf.rfilter_in = {
        "area": ospf.rfilter_in['area'],
        "pid": ospf.rfilter_in['pid'],
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3].strip() \
            .replace('[%ospfPID]', "".join(ospf.rfilter_in['pid']), 1) \
            .replace('[%ospfArea]', "".join(ospf.rfilter_in['area']), 1)),
        "cvss": (cvssMetrics)}

    if ospf.rfilter_out['must_report'] == True:
        items = search_xml('ospfRouteFilteringOut')
        cvssMetrics = str(cvss_score(items[5]))
        ospf.rfilter_out = {
        "area": ospf.rfilter_out['area'],
        "pid": ospf.rfilter_out['pid'],
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3].strip() \
            .replace('[%ospfPID]', "".join(ospf.rfilter_out['pid']), 1) \
            .replace('[%ospfArea]', "".join(ospf.rfilter_out['area']), 1)),
        "cvss": (cvssMetrics)}

    if ospf.maxLSA['must_report'] == True:
        items = search_xml('ospfMaxLSA')
        cvssMetrics = str(cvss_score(items[5]))
        ospf.maxLSA = {
        "pid": ospf.maxLSA['pid'],
        "must_report": True,
        "fixImpact": (items[0]),
        "definition": (items[1]),
        "threatInfo": (items[2]),
        "howtofix": (items[3].strip() \
            .replace('[%ospfInstance]', "".join(ospf.maxLSA['pid']), 1)),
        "cvss": (cvssMetrics)}

    toBeReturned = ''
    if ospf.passive['must_report'] == True:
        toBeReturned = ospf.passive['definition'] + '\n' + ospf.passive['threatInfo'] + '\n\n' + ospf.passive['howtofix'] + '\n'
    if ospf.auth_md5['must_report'] == True:
        toBeReturned = toBeReturned + ospf.auth_md5['definition'] + '\n' + ospf.auth_md5['threatInfo'] + '\n\n' + ospf.auth_md5['howtofix'] + '\n'
    if ospf.rfilter_in['must_report'] == True:
        toBeReturned = toBeReturned + ospf.rfilter_in['definition'] + '\n' + ospf.rfilter_in['threatInfo'] + '\n\n' + ospf.rfilter_in['howtofix'] + '\n'
    if ospf.rfilter_out['must_report'] == True:
        toBeReturned = toBeReturned + ospf.rfilter_out['definition'] + '\n' + ospf.rfilter_out['threatInfo'] + '\n\n' + ospf.rfilter_out['howtofix'] + '\n'
    if ospf.maxLSA['must_report'] == True:
        toBeReturned = toBeReturned + ospf.maxLSA['definition'] + '\n' + ospf.maxLSA['threatInfo'] + '\n\n' + ospf.maxLSA['howtofix'] + '\n'

    return toBeReturned

