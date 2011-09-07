# -*- coding: iso-8859-1 -*-

__docformat__ = 'restructuredtext'
__version__ = '$Id$'

import __builtin__
from routerdefense.common import *

from xml import *

def engine_glbp(lines, glbp, ifaceCfg):
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


def engine_hsrp(lines, hsrp, ifaceCfg):
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

def engine_vrrp(lines, vrrp, ifaceCfg):
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
