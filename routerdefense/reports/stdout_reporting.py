# -*- coding: iso-8859-1 -*-

from routerdefense.common import *
from routerdefense.metrics import *

def add(title, comment):
    strippedLine = line.lstrip().rstrip()
    return strippedLine

def stdout_header():
    """Write header at the beginning of stdout."""    
    header = """
______            _             ______      __
| ___ \          | |            |  _  \    / _|
| |_/ /___  _   _| |_ ___ _ __  | | | |___| |_ ___ _ __  ___  ___
|    // _ \| | | | __/ _ \ '__| | | | / _ \  _/ _ \ '_ \/ __|/ _ \
| |\ \ (_) | |_| | ||  __/ |    | |/ /  __/ ||  __/ | | \__ \  __/
\_| \_\___/ \__,_|\__\___|_|    |___/ \___|_| \___|_| |_|___/\___|

=[ Cisco IOS security assessment tool
=[ http://code.google.com/p/routerdefense
=[ version 2011.9

"""
    return header;

def stdout_footer():
    """Write Footer at the end of stdout."""
    footer = 'Arrivederci!'
    return "\n" + footer;

def stdout_report(generic, mgmt_plane, ctrl_plane, data_plane):
    """Generate the stdout report."""
    summary = list()
    vty_already_reported = False
    try:

        print stdout_banner('Generic information')
        print ""
        print "    => Hostname: %s" % generic.hostName
        print "    => IOS version: %s" % generic.iosVersion
        print "    => Switching: %s" % generic.switchingMethod
        print "    => Multicast: %s" % generic.multicast
        print "    => QoS: %s" % generic.qos
        print "    => IPv6: %s" % generic.ipv6
        print "    => IPSEC VPN: %s" % generic.ipsec

        print stdout_category_banner('ManagementPlane')
        summary.append('\nManagement Plane\n')
        for name in mgmt_plane:
            counter = 0
            total = 0
            if name != 'interface':
                print stdout_banner(name.long_name)
                for k,v in inspect.getmembers(name):
                    if isinstance(v, dict):
                        total = total + 1
                        if v['must_report'] == True:
                            counter = counter + 1
                            defn = v['definition'].strip()
                            threatInfo = v['threatInfo'].strip()
                            howtofix = v['howtofix'].strip()
                            fiximpact = v['fixImpact'].strip()
                            cvss = v['cvss'].strip()
                            print stdout_content(
                            defn,
                            threatInfo,
                            howtofix,
                            fiximpact,
                            cvss
                            )

                print '\nNumber of threatInfo(s) to fix: %d/%d' % \
                (counter, total)
                if ( (name.long_name == 'Vty lines') and
                (vty_already_reported == False)):
                    summary.append('%s: %d/%d' % \
                    (name.long_name, counter, total))
                    vty_already_reported = True
                elif ( (name.long_name == 'Vty lines') and
                (vty_already_reported == True)):
                    pass
                else:
                    summary.append('%s: %d/%d' % \
                    (name.long_name, counter, total))

        print stdout_category_banner('ControlPlane')
        summary.append('\nControl Plane\n')
        for name in ctrl_plane:
            total = 0
            counter = 0
            if name != 'interface':
                print stdout_banner(name.long_name)
                for k,v in inspect.getmembers(name):
                    if isinstance(v, dict):
                        total = total + 1
                        if v['must_report'] == True:
                            counter = counter + 1
                            defn = v['definition'].strip()
                            threatInfo = v['threatInfo'].strip()
                            fiximpact = v['fixImpact'].strip()
                            cvss = v['cvss'].strip()
                            if defn == \
                            'OSPF route filtering in':
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%ospfPID]', ", " \
                                .join(name.rfilter_in['pid']), 1)
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%ospfArea]', ", " \
                                .join(name.rfilter_in['area']), 1)
                            elif defn == \
                            'OSPF MD5 authentication':
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%ospfInterface]', ", " \
                                .join(name.auth_md5['interfaces']), 1)
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%ospfArea]', ", " \
                                .join(name.auth_md5['area']), 1)
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%ospfPID]', ", " \
                                .join(name.auth_md5['pid']), 1)
                            elif defn == \
                            'OSPF route filtering out':
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%ospfPID]', ", " \
                                .join(name.rfilter_out['pid']), 1)
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%ospfArea]', ", " \
                                .join(name.rfilter_out['area']), 1)
                            elif defn == \
                            'OSPF passive interface default':
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%ospfInstance]', ", " \
                                .join(name.passive['pid']), 1)
                            elif defn == \
                            'OSPF maximum LSA':
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%ospfInstance]', ", " \
                                .join(name.maxLSA['pid']), 1)
                            elif defn == \
                            'EIGRP MD5 authentication':
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%eigrpInterface]', ", " \
                                .join(name.auth_md5['interfaces']), 1)
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%eigrpAs]', ", " \
                                .join(name.auth_md5['asn']), 1)
                            elif defn == \
                            'EIGRP passive interface default':
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%eigrpAs]', ", " \
                                .join(name.passive['asn']), 1)
                            elif defn == \
                            'EIGRP route filtering inbound':
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%eigrpAs]', ", " \
                                .join(name.rfilter_in['asn']), 1)
                            elif defn == \
                            'EIGRP route filtering outbound':
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%eigrpAs]', ", " \
                                .join(name.rfilter_out['asn']), 1)
                            elif defn == \
                            'RIP MD5 authentication':
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%ripInterface]', ", " \
                                .join(name.auth_md5['interfaces']), 1)
                            howtofix = v['howtofix']
                            print stdout_content(
                            defn,
                            threatInfo,
                            howtofix,
                            fiximpact,
                            cvss
                            )

                print '\nNumber of threatInfo(s) to fix: %d/%d' % \
                (counter, total)
                summary.append('%s: %d/%d' % \
                (name.long_name, counter, total))


        print stdout_category_banner('DataPlane')
        summary.append('\nData Plane\n')

        for name in data_plane:
            total = 0
            counter = 0
            if name != 'interface':
                print stdout_banner(name.long_name)
                for k,v in inspect.getmembers(name):
                    if isinstance(v, dict):
                        total = total + 1
                        if v['must_report'] == True:
                            counter = counter + 1
                            definition = v['definition'].strip()
                            threatInfo = v['threatInfo'].strip()
                            fiximpact = v['fixImpact'].strip()
                            cvss = v['cvss'].strip()
                            if definition == \
                            'Port security violation':
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%interface]', ", " \
                                .join(name.violation['candidates']), 1)
                            if definition == \
                            'Port security MAC address sticky':
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%interface]', ", " \
                                .join(name.sticky['candidates']), 1)
                            if definition == \
                            'Port security total maximum MAC addresses':
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%interface]', ", " \
                                .join( \
                                name.maximumTotal['candidates']), 1)
                            if definition == \
                            'Port security access vlan \
                            maximum MAC addresses':
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%interface]', ", " \
                                .join( \
                                name.maximumAccess['candidates']), 1)
                            if definition == \
                            'Port security voice vlan \
                            maximum MAC addresses':
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%interface]', ", " \
                                .join( \
                                name.maximumVoice['candidates']), 1)
                            if definition == 'DTP negotiation':
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%interface]', ", " \
                                .join( \
                                name.nonegotiate['candidates']), 1)
                            if definition == 'Flow Control 802.3x':
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%interface]', ", " \
                                .join( \
                                name.flowcontrol['candidates']), 1)
                            if definition == 'VLAN 1':
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%interface]', ", " \
                                .join(name.vlan1['candidates']), 1)
                            if definition == 'Unused ports':
                                v['howtofix'] = \
                                v['howtofix'].strip() \
                                .replace('[%interface]', ", " \
                                .join( \
                                name.unusedports['candidates']), 1)

                            howtofix = v['howtofix']
                            print stdout_content(
                            definition,
                            threatInfo,
                            howtofix,
                            fiximpact,
                            cvss
                            )

                print '\nNumber of threatInfo(s) to fix: %d/%d' % \
                (counter, total)
                summary.append('%s: %d/%d' % \
                (name.long_name, counter, total))



        print '\n=[ summary ]='
        for entry in summary:
            print entry

    except:
        return "error while genefixImpact stdout audit output."

    return "stdout"
