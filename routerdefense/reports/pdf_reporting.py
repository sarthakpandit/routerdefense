# -*- coding: iso-8859-1 -*-

from routerdefense.common import *
from routerdefense.metrics import *

def pdfReport(outputFile, genericCfg, ManagementPlaneMetrics, ControlPlaneMetrics, DataPlaneMetrics):
    from reportlab.pdfgen import canvas
    from reportlab.lib.enums import TA_JUSTIFY
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    import time
    import inspect
    import __builtin__
    
    doc = SimpleDocTemplate(outputFile) 
    report = []
    logo = "logo-router-defense.png"
    im = Image(logo)
    formatted_time = time.ctime()
    intro = """
    <font size=12>Some of those recommandations could not fit with your environment for any reason from layer 1 to layer 8 (financial) and layer 9 (political).
    </font>
    """
    
    outro = """RouterDefense is created and maintained by Francois Ropert.<br />
    <a href='http://code.google.com/p/routerdefense'>http://code.google.com/p/routerdefense</a> 
    """
    report.append(im)
    report.append(Spacer(1, 24))
    styles=getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Justify', alignment=TA_JUSTIFY))
    ptext = '<font size=12>Report generation date: <b> %s </b></font>' % formatted_time
    report.append(Paragraph(ptext, styles["Justify"]))
    ptext = '<font size=12>%s</font>' % intro
    report.append(Paragraph(ptext, styles["Justify"]))
    report.append(Spacer(1, 24))

    ptext = '<font size=14><b><u>Hostname:</u></b> %s </font><br />' % genericCfg.hostName
    ptext += '<font size=14><b><u>IOS:</u></b> %s </font><br />' % genericCfg.iosVersion
    ptext += '<font size=14><b><u>Switching:</u></b> %s </font><br />' % genericCfg.switchingMethod
    ptext += '<font size=14><b><u>Multicast:</u></b> %s </font><br />' % genericCfg.multicast
    ptext += '<font size=14><b><u>QoS:</u></b> %s </font><br />' % genericCfg.qos
    ptext += '<font size=14><b><u>IPv6:</u></b> %s </font><br />' % genericCfg.ipv6
    ptext += '<font size=14><b><u>IPSEC VPN:</u></b> %s </font><br />' % genericCfg.ipsec
    report.append(Paragraph(ptext, styles["Justify"]))
    
    report.append(Spacer(1, 24))
    ptext = '<font size=20>Management Plane</font>'
    report.append(Paragraph(ptext, styles["Justify"]))
    report.append(Spacer(1, 24))

    for name in ManagementPlaneMetrics:
        if name != 'interface':
            for k,v in inspect.getmembers(name):
                if isinstance(v, dict):
                    if v['must_report'] == True:
                        definition = v['definition'].strip()
                        threatInfo = v['threatInfo'].strip()
                        howtofix = v['howtofix'].strip()
                        fixImpact = v['fixImpact'].strip()
                        cvss = v['cvss'].strip()

                        ptext = '<font size=12><u>%s</u> <b>%s</b></font><br />' % (name.long_name, definition)
                        report.append(Paragraph(ptext, styles["Justify"]))
                        report.append(Spacer(1, 6))
                        ptext = '<font size=12><u>Threat:</u> %s (Score: %s)</font><br />' % (threatInfo, cvss)
                        report.append(Paragraph(ptext, styles["Justify"]))
                        report.append(Spacer(1, 6))
                        ptext = '<font size=12><u>Fix impact:</u> %s</font><br />' % fixImpact
                        report.append(Paragraph(ptext, styles["Justify"]))
                        report.append(Spacer(1, 6))
                        ptext = '<font size=14><b><u>How to fix:</u></b> %s </font><br />' % howtofix
                        report.append(Paragraph(ptext, styles["Justify"]))
                        report.append(Spacer(1, 12))

    report.append(Spacer(1, 24))
    ptext = '<font size=20>Control Plane</font>'
    report.append(Paragraph(ptext, styles["Justify"]))
    report.append(Spacer(1, 24))
    for name in ControlPlaneMetrics:
        if name != 'interface':
            for k,v in inspect.getmembers(name):
                if isinstance(v, dict):
                    if v['must_report'] == True:
                        definition = v['definition'].strip()
                        threatInfo = v['threatInfo'].strip()
                        fixImpact = v['fixImpact'].strip()
                        cvss = v['cvss'].strip()
                        if definition == 'OSPF route filtering in':
                            v['howtofix'] = v['howtofix'].strip().replace('[%ospfPID]', ", ".join(name.rfilter_in['pid']), 1)
                            v['howtofix'] = v['howtofix'].strip().replace('[%ospfArea]', ", ".join(name.rfilter_in['area']), 1)
                        elif definition == 'OSPF MD5 authentication':
                            v['howtofix'] = v['howtofix'].strip().replace('[%ospfInterface]', ", ".join(name.auth_md5['interfaces']), 1)
                            v['howtofix'] = v['howtofix'].strip().replace('[%ospfArea]', ", ".join(name.auth_md5['area']), 1)
                            v['howtofix'] = v['howtofix'].strip().replace('[%ospfPID]', ", ".join(name.auth_md5['pid']), 1)
                        elif definition == 'OSPF route filtering out':
                            v['howtofix'] = v['howtofix'].strip().replace('[%ospfPID]', ", ".join(name.rfilter_out['pid']), 1)
                            v['howtofix'] = v['howtofix'].strip().replace('[%ospfArea]', ", ".join(name.rfilter_out['area']), 1)
                        elif definition == 'OSPF passive interface default':
                            v['howtofix'] = v['howtofix'].strip().replace('[%ospfInstance]', ", ".join(name.passive['pid']), 1)                          
                        elif definition == 'OSPF maximum LSA':
                            v['howtofix'] = v['howtofix'].strip().replace('[%ospfInstance]', ", ".join(name.maxLSA['pid']), 1)                          
                        elif definition == 'EIGRP MD5 authentication':
                            v['howtofix'] = v['howtofix'].strip().replace('[%eigrpInterface]', ", ".join(name.auth_md5['interfaces']), 1)
                            v['howtofix'] = v['howtofix'].strip().replace('[%eigrpAs]', ", ".join(name.auth_md5['asn']), 1)
                        elif definition == 'EIGRP passive interface default':
                            v['howtofix'] = v['howtofix'].strip().replace('[%eigrpAs]', ", ".join(name.passive['asn']), 1)
                        elif definition == 'EIGRP route filtering inbound':
                            v['howtofix'] = v['howtofix'].strip().replace('[%eigrpAs]', ", ".join(name.rfilter_in['asn']), 1)
                        elif definition == 'EIGRP route filtering outbound':
                            v['howtofix'] = v['howtofix'].strip().replace('[%eigrpAs]', ", ".join(name.rfilter_out['asn']), 1)
                        elif definition == 'RIP MD5 authentication':
                            v['howtofix'] = v['howtofix'].strip().replace('[%ripInterface]', ", ".join(name.auth_md5['interfaces']), 1)
                        howtofix = v['howtofix']
                        
                        ptext = '<font size=12><u>%s</u> <b>%s</b></font><br />' % (name.long_name, definition)
                        report.append(Paragraph(ptext, styles["Justify"]))
                        report.append(Spacer(1, 6))
                        ptext = '<font size=12><u>Threat:</u> %s (Score: %s)</font><br />' % (threatInfo, cvss)
                        report.append(Paragraph(ptext, styles["Justify"]))
                        report.append(Spacer(1, 6))
                        ptext = '<font size=12><u>Fix impact:</u> %s</font><br />' % fixImpact
                        report.append(Paragraph(ptext, styles["Justify"]))
                        report.append(Spacer(1, 6))
                        ptext = '<font size=14><b><u>How to fix:</u></b> %s </font><br />' % howtofix
                        report.append(Paragraph(ptext, styles["Justify"]))
                        report.append(Spacer(1, 12))

    report.append(Spacer(1, 24))
    ptext = '<font size=20>Data Plane</font>'
    report.append(Paragraph(ptext, styles["Justify"]))
    report.append(Spacer(1, 24))
    for name in DataPlaneMetrics:
        if name != 'interface':
            for k,v in inspect.getmembers(name):
                if isinstance(v, dict):
                    if v['must_report'] == True:
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
                    
                        ptext = '<font size=12><u>%s</u> <b>%s</b></font><br />' % (name.long_name, definition)
                        report.append(Paragraph(ptext, styles["Justify"]))
                        report.append(Spacer(1, 6))
                        ptext = '<font size=12><u>Threat:</u> %s (Score: %s)</font><br />' % (threatInfo, cvss)
                        report.append(Paragraph(ptext, styles["Justify"]))
                        report.append(Spacer(1, 6))
                        ptext = '<font size=12><u>Fix impact:</u> %s</font><br />' % fixImpact
                        report.append(Paragraph(ptext, styles["Justify"]))
                        report.append(Spacer(1, 6))
                        ptext = '<font size=14><b><u>How to fix:</u></b> %s </font><br />' % howtofix
                        report.append(Paragraph(ptext, styles["Justify"]))
                        report.append(Spacer(1, 12))


    ptext = outro
    report.append(Paragraph(ptext, styles["Justify"]))
    
    doc.build(report)
    
    print "Audit has been saved under the filename: %s " % outputFile 
    return "PDF"

