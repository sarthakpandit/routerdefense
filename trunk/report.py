# -*- coding: iso-8859-15 -*-

from common import *
from metrics import *
from reporthtml import htmlReport
from reportpdf import pdfReport
from reportcsv import csvReport
import inspect
import __builtin__

def add(title, comment):
    strippedLine = line.lstrip().rstrip()
    return strippedLine

def stdoutput():
    print "Hello World!"

def writeHeader():
    header = """
______            _             ______      __
| ___ \          | |            |  _  \    / _|
| |_/ /___  _   _| |_ ___ _ __  | | | |___| |_ ___ _ __  ___  ___
|    // _ \| | | | __/ _ \ '__| | | | / _ \  _/ _ \ '_ \/ __|/ _ \
| |\ \ (_) | |_| | ||  __/ |    | |/ /  __/ ||  __/ | | \__ \  __/
\_| \_\___/ \__,_|\__\___|_|    |___/ \___|_| \___|_| |_|___/\___|

=[ Cisco IOS security assessment tool
=[ http://www.packetfault.org
=[ version 0.5.1
"""
    return header;

def writeFooter():
    footer = 'Bye!'
    return "\n" + footer;

def stdoutReport(genericCfg, ManagementPlaneMetrics, ControlPlaneMetrics, DataPlaneMetrics):

    summaryTable = list()
    vtyAlreadyReported = False
    try:

        print createStdoutBanner('Generic information')
        print ""
        print "    => Hostname: %s" % genericCfg.hostName
        print "    => IOS version: %s" % genericCfg.iosVersion
        print "    => Switching: %s" % genericCfg.switchingMethod
        print "    => Multicast: %s" % genericCfg.multicast
        print "    => QoS: %s" % genericCfg.qos
        print "    => IPv6: %s" % genericCfg.ipv6
        print "    => IPSEC VPN: %s" % genericCfg.ipsec

        print createStdoutCatBanner('ManagementPlane')
        summaryTable.append('\nManagement Plane\n')
        for name in ManagementPlaneMetrics:
            counter = 0
            total = 0
            if name != 'interface':
                print createStdoutBanner(name.longName)
                for k,v in inspect.getmembers(name):
                    if isinstance(v, dict):
                        total = total + 1
                        if v['mustBeReported'] == True:
                            counter = counter + 1
                            definition = v['definition'].strip()
                            threatInfo = v['threatInfo'].strip()
                            howtofix = v['howtofix'].strip()
                            fixImpact = v['fixImpact'].strip()
                            cvss = v['cvss'].strip()
                            print formatStdoutContent(definition, threatInfo, howtofix, fixImpact, cvss)

                print '\nNumber of threat(s) to fix: %d/%d' % (counter, total)
                if ( (name.longName == 'Vty lines') and (vtyAlreadyReported == False)):
                    summaryTable.append('%s: %d/%d' % (name.longName, counter, total))
                    vtyAlreadyReported = True
                elif ( (name.longName == 'Vty lines') and (vtyAlreadyReported == True)):
                    pass
                else:
                    summaryTable.append('%s: %d/%d' % (name.longName, counter, total))

        print createStdoutCatBanner('ControlPlane')
        summaryTable.append('\nControl Plane\n')
        for name in ControlPlaneMetrics:
            total = 0
            counter = 0
            if name != 'interface':
                print createStdoutBanner(name.longName)
                for k,v in inspect.getmembers(name):
                    if isinstance(v, dict):
                        total = total + 1
                        if v['mustBeReported'] == True:
                            counter = counter + 1
                            definition = v['definition'].strip()
                            threatInfo = v['threatInfo'].strip()
                            fixImpact = v['fixImpact'].strip()
                            cvss = v['cvss'].strip()
                            if definition == 'OSPF route filtering in':
                                v['howtofix'] = v['howtofix'].strip().replace('[%ospfPID]', ", ".join(name.routeFilteringIn['pid']), 1)
                                v['howtofix'] = v['howtofix'].strip().replace('[%ospfArea]', ", ".join(name.routeFilteringIn['area']), 1)
                            elif definition == 'OSPF MD5 authentication':
                                v['howtofix'] = v['howtofix'].strip().replace('[%ospfInterface]', ", ".join(name.authModeMD5['interfaces']), 1)
                                v['howtofix'] = v['howtofix'].strip().replace('[%ospfArea]', ", ".join(name.authModeMD5['area']), 1)
                                v['howtofix'] = v['howtofix'].strip().replace('[%ospfPID]', ", ".join(name.authModeMD5['pid']), 1)
                            elif definition == 'OSPF route filtering out':
                                v['howtofix'] = v['howtofix'].strip().replace('[%ospfPID]', ", ".join(name.routeFilteringOut['pid']), 1)
                                v['howtofix'] = v['howtofix'].strip().replace('[%ospfArea]', ", ".join(name.routeFilteringOut['area']), 1)
                            elif definition == 'OSPF passive interface default':
                                v['howtofix'] = v['howtofix'].strip().replace('[%ospfInstance]', ", ".join(name.passiveDefault['pid']), 1)
                            elif definition == 'OSPF maximum LSA':
                                v['howtofix'] = v['howtofix'].strip().replace('[%ospfInstance]', ", ".join(name.maxLSA['pid']), 1)
                            elif definition == 'EIGRP MD5 authentication':
                                v['howtofix'] = v['howtofix'].strip().replace('[%eigrpInterface]', ", ".join(name.authModeMD5['interfaces']), 1)
                                v['howtofix'] = v['howtofix'].strip().replace('[%eigrpAs]', ", ".join(name.authModeMD5['asn']), 1)
                            elif definition == 'EIGRP passive interface default':
                                v['howtofix'] = v['howtofix'].strip().replace('[%eigrpAs]', ", ".join(name.passiveDefault['asn']), 1)
                            elif definition == 'EIGRP route filtering inbound':
                                v['howtofix'] = v['howtofix'].strip().replace('[%eigrpAs]', ", ".join(name.routeFilteringIn['asn']), 1)
                            elif definition == 'EIGRP route filtering outbound':
                                v['howtofix'] = v['howtofix'].strip().replace('[%eigrpAs]', ", ".join(name.routeFilteringOut['asn']), 1)
                            elif definition == 'RIP MD5 authentication':
                                v['howtofix'] = v['howtofix'].strip().replace('[%ripInterface]', ", ".join(name.authModeMD5['interfaces']), 1)

                            howtofix = v['howtofix']
                            print formatStdoutContent(definition, threatInfo, howtofix, fixImpact, cvss)

                print '\nNumber of threat(s) to fix: %d/%d' % (counter, total)
                summaryTable.append('%s: %d/%d' % (name.longName, counter, total))


        print createStdoutCatBanner('DataPlane')
        summaryTable.append('\nData Plane\n')

        for name in DataPlaneMetrics:
            total = 0
            counter = 0
            if name != 'interface':
                print createStdoutBanner(name.longName)
                for k,v in inspect.getmembers(name):
                    if isinstance(v, dict):
                        total = total + 1
                        if v['mustBeReported'] == True:
                            counter = counter + 1
                            definition = v['definition'].strip()
                            threatInfo = v['threatInfo'].strip()
                            fixImpact = v['fixImpact'].strip()
                            cvss = v['cvss'].strip()
                            if definition == 'Port security violation':
                                v['howtofix'] = v['howtofix'].strip().replace('[%interface]', ", ".join(name.violation['candidates']), 1)
                            if definition == 'Port security MAC address sticky':
                                v['howtofix'] = v['howtofix'].strip().replace('[%interface]', ", ".join(name.sticky['candidates']), 1)
                            if definition == 'Port security total maximum MAC addresses':
                                v['howtofix'] = v['howtofix'].strip().replace('[%interface]', ", ".join(name.maximumTotal['candidates']), 1)
                            if definition == 'Port security access vlan maximum MAC addresses':
                                v['howtofix'] = v['howtofix'].strip().replace('[%interface]', ", ".join(name.maximumAccess['candidates']), 1)
                            if definition == 'Port security voice vlan maximum MAC addresses':
                                v['howtofix'] = v['howtofix'].strip().replace('[%interface]', ", ".join(name.maximumVoice['candidates']), 1)
                            if definition == 'DTP negotiation':
                                v['howtofix'] = v['howtofix'].strip().replace('[%interface]', ", ".join(name.nonegotiate['candidates']), 1)
                            if definition == 'Flow Control 802.3x':
                                v['howtofix'] = v['howtofix'].strip().replace('[%interface]', ", ".join(name.flowcontrol['candidates']), 1)
                            if definition == 'VLAN 1':
                                v['howtofix'] = v['howtofix'].strip().replace('[%interface]', ", ".join(name.vlan1['candidates']), 1)
                            if definition == 'Unused ports':
                                v['howtofix'] = v['howtofix'].strip().replace('[%interface]', ", ".join(name.unusedports['candidates']), 1)

                            howtofix = v['howtofix']
                            print formatStdoutContent(definition, threatInfo, howtofix, fixImpact, cvss)

                print '\nNumber of threat(s) to fix: %d/%d' % (counter, total)
                summaryTable.append('%s: %d/%d' % (name.longName, counter, total))



        print '\n=[ summary ]='
        for entry in summaryTable:
            print entry

    except:
        return "error while genefixImpact stdout audit output."

    return "stdout"
