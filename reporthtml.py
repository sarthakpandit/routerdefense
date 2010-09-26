# -*- coding: iso-8859-15 -*-

def htmlReport(outputFile,genericCfg, ManagementPlaneMetrics, ControlPlaneMetrics, DataPlaneMetrics):
	import time
	import inspect
	import __builtin__
	date = time.strftime('%D')
	try:
		report = open(outputFile, 'w')
	except IOError:
		print "Error while accessing the Output file. Perhaps you should check the file permissions ;)"
		exit(1)
	htmlHeader = []
	htmlFooter = []
	htmlSummary = []
	htmlTOC = []
	htmlMPlane = []
	htmlCPlane = []
	htmlDPlane = []
	
	MPlaneCounter = 0
	CPlaneCounter = 0
	DPlaneCounter = 0
	
	htmlTOC.append('<div id="toc">')
	htmlTOC.append('<ol>')

	htmlSummary.append('<div id="summary">')
	htmlSummary.append('<table')
	htmlSummary.append('<thead><tr><th>Management Plane</th><th>Control Plane</th><th>Data Plane</th></tr></thead>')
	htmlSummary.append('<tbody>')

	htmlHeader.append('<!DOCTYPE html>')
	htmlHeader.append('<head>')
	htmlHeader.append('<title>'+ 'RouterDefense ' + date + '</title>')
	htmlHeader.append('<link rel="stylesheet" media="all" href="style.css" />')
	htmlHeader.append('</head>')
	htmlHeader.append('<body>')
	htmlHeader.append('<div id="content">')
	htmlHeader.append('<header role="banner">')
	
	htmlHeader.append('<h1><a href="http://www.packetfault.org">Router <span>Defense</span></a></h1>')
	htmlHeader.append('<nav role="navigation"><a href=#MPlane>Management Plane</a>  <a href=#CPlane>Control Plane</a>  <a href=#DPlane>Data Plane</a></nav>')
	htmlHeader.append('</header>')
	htmlHeader.append('<p id="presentation">')
	htmlHeader.append('Some of those recommandations could not fit with your environment for any reason from layer 1 to layer 9.')
	htmlHeader.append('</p>')
	htmlHeader.append('<section class="content">')

	htmlHeader.append('<table>')
	htmlHeader.append('<thead>')
	htmlHeader.append('<tr><th>Hostname</th><th>IOS</th><th>Switching</th><th>Multicast</th><th>QoS</th><th>IPv6</th><th>IPSEC VPN</th></tr>')
	htmlHeader.append('</thead>')
	htmlHeader.append('<tbody>')
	htmlHeader.append('<tr>')
	htmlHeader.append('<td>' + genericCfg.hostName + '</td>')
	htmlHeader.append('<td>' + genericCfg.iosVersion + '</td>')
	htmlHeader.append('<td>' + genericCfg.switchingMethod + '</td>')
	htmlHeader.append('<td>' + genericCfg.multicast + '</td>')
	htmlHeader.append('<td>' + genericCfg.qos + '</td>')
	htmlHeader.append('<td>' + genericCfg.ipv6 + '</td>')
	htmlHeader.append('<td>' + genericCfg.ipsec + '</td>')
	htmlHeader.append('</tr>')
	htmlHeader.append('</tbody>')
	htmlHeader.append('</table>')
	htmlHeader.append('<br />')	

	htmlMPlane.append('<a id="planeTitle" name="MPlane">Management Plane</a><br /><br />')
	for name in ManagementPlaneMetrics:
		if name != 'interface':
			for k,v in inspect.getmembers(name):
				if isinstance(v, dict):
					if v['mustBeReported'] == True:
						definition = v['definition'].strip()
						threatInfo = v['threatInfo'].strip()
						howtofix = v['howtofix'].split('\n')
						fixImpact = v['fixImpact'].strip()
						cvss = v['cvss'].strip()
						htmlMPlane.append('<table id="namedef">')
						htmlMPlane.append('<tbody>')
						htmlMPlane.append('<tr>')
						htmlMPlane.append('<a id="planeContent" name="MP'+ str(MPlaneCounter) +'">' + '<td id="name">' + name.longName + '</td>' + '</a>')
						htmlMPlane.append('<td id="definition">' + definition + '</td>')
						if float(cvss) <= 4:
							htmlMPlane.append('<td id="cvssGreen">' + cvss + '/10' + '</td>')
						elif float(cvss) <= 7.9 and cvss >=4.1:
							htmlMPlane.append('<td id="cvssOrange">' + cvss + '/10' + '</td>')
						elif float(cvss) >=8:
							htmlMPlane.append('<td id="cvssRed">' + cvss + '/10' + '</td>')							
						htmlMPlane.append('</tr>')
						htmlMPlane.append('</tbody>')
						htmlMPlane.append('</table>')

						htmlMPlane.append('<p id="threatInfo">Threat information: </p>' + threatInfo + '<br />')
						htmlMPlane.append('<p id="threatInfo">Fix impact: </p>' + fixImpact + '<br />')

						htmlMPlane.append('<table id ="fix">')
						htmlMPlane.append('<thead>')
						htmlMPlane.append('<tr><th id="fix">How to fix</th></tr>')
						htmlMPlane.append('</thead>')
						htmlMPlane.append('<tbody>')
						for index in howtofix:
							htmlMPlane.append('<tr>')
							htmlMPlane.append('<td id="fix">' + index + '</td>')
							htmlMPlane.append('</tr>')
						htmlMPlane.append('</tbody>')
						htmlMPlane.append('</table>')
						htmlMPlane.append('</p></article><br />')

						htmlTOC.append('<li><a href=#MP'+ str(MPlaneCounter) + '>' + definition + '</a></li>')
						MPlaneCounter = MPlaneCounter + 1
							
	htmlCPlane.append('<a id="planeTitle" name="CPlane">Control Plane</a><br /><br />')	
	for name in ControlPlaneMetrics:
		if name != 'interface':
			for k,v in inspect.getmembers(name):
				if isinstance(v, dict):
					if v['mustBeReported'] == True:
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

						howtofix = v['howtofix'].split('\n')
						htmlCPlane.append('<table id="namedef">')
						htmlCPlane.append('<tbody>')
						htmlCPlane.append('<tr>')
						htmlCPlane.append('<a id="planeContent" name="CP'+ str(CPlaneCounter) +'">' + '<td id="name">' + name.longName + '</td>' + '</a>')
						htmlCPlane.append('<td id="definition">' + definition + '</td>')
						if float(cvss) <= 4:
							htmlCPlane.append('<td id="cvssGreen">' + cvss + '/10' + '</td>')
						elif float(cvss) <= 7.9 and cvss >=4.1:
							htmlCPlane.append('<td id="cvssOrange">' + cvss + '/10' + '</td>')
						elif float(cvss) >=8:
							htmlCPlane.append('<td id="cvssRed">' + cvss + '/10' + '</td>')							
						htmlCPlane.append('</tr>')
						htmlCPlane.append('</tbody>')
						htmlCPlane.append('</table>')

						htmlCPlane.append('<p id="threatInfo">Threat information: </p>' + threatInfo + '<br />')
						htmlCPlane.append('<p id="threatInfo">Fix impact: </p>' + fixImpact + '<br />')

						htmlCPlane.append('<table id ="fix">')
						htmlCPlane.append('<thead>')
						htmlCPlane.append('<tr><th id="fix">How to fix</th></tr>')
						htmlCPlane.append('</thead>')
						htmlCPlane.append('<tbody>')
						for index in howtofix:
							htmlCPlane.append('<tr>')
							htmlCPlane.append('<td id="fix">' + index + '</td>')
							htmlCPlane.append('</tr>')
						htmlCPlane.append('</tbody>')
						htmlCPlane.append('</table>')
						htmlCPlane.append('</p></article><br />')

						htmlTOC.append('<li><a href=#CP'+ str(CPlaneCounter) + '>' + definition + '</a></li>')
						CPlaneCounter = CPlaneCounter + 1

	htmlDPlane.append('<a id="planeTitle" name="DPlane">Data Plane</a><br /><br />')	
	for name in DataPlaneMetrics:
		if name != 'interface':
			for k,v in inspect.getmembers(name):
				if isinstance(v, dict):
					if v['mustBeReported'] == True:
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

						howtofix = v['howtofix'].split('\n')
						htmlDPlane.append('<table id="namedef">')
						htmlDPlane.append('<tbody>')
						htmlDPlane.append('<tr>')
						htmlDPlane.append('<a id="planeContent" name="DP'+ str(DPlaneCounter) +'">' + '<td id="name">' + name.longName + '</td>' + '</a>')
						htmlDPlane.append('<td id="definition">' + definition + '</td>')
						if float(cvss) <= 4:
							htmlDPlane.append('<td id="cvssGreen">' + cvss + '/10' + '</td>')
						elif float(cvss) <= 7.9 and cvss >=4.1:
							htmlDPlane.append('<td id="cvssOrange">' + cvss + '/10' + '</td>')
						elif float(cvss) >=8:
							htmlDPlane.append('<td id="cvssRed">' + cvss + '/10' + '</td>')							
						htmlDPlane.append('</tr>')
						htmlDPlane.append('</tbody>')
						htmlDPlane.append('</table>')

						htmlDPlane.append('<p id="threatInfo">Threat information: </p>' + threatInfo + '<br />')
						htmlDPlane.append('<p id="threatInfo">Fix impact: </p>' + fixImpact + '<br />')

						htmlDPlane.append('<table id ="fix">')
						htmlDPlane.append('<thead>')
						htmlDPlane.append('<tr><th id="fix">How to fix</th></tr>')
						htmlDPlane.append('</thead>')
						htmlDPlane.append('<tbody>')
						for index in howtofix:
							htmlDPlane.append('<tr>')
							htmlDPlane.append('<td id="fix">' + index + '</td>')
							htmlDPlane.append('</tr>')
						htmlDPlane.append('</tbody>')
						htmlDPlane.append('</table>')
						htmlDPlane.append('</p></article><br />')

						htmlTOC.append('<li><a href=#DP'+ str(DPlaneCounter) + '>' + definition + '</a></li>')
						DPlaneCounter = DPlaneCounter + 1


	htmlSummary.append('<tr>')
	htmlSummary.append('<td>' + str(MPlaneCounter) + '</td>')
	htmlSummary.append('<td>' + str(CPlaneCounter) + '</td>')
	htmlSummary.append('<td>' + str(DPlaneCounter) + '</td>')	
	htmlSummary.append('</tr>')
	
	htmlSummary.append('</tbody>')
	htmlSummary.append('</table>')
	htmlSummary.append('</div>')
	
	htmlSummary.append('<u>Management plane:</u> impact on management.<br /><u>Control plane:</u> impact on infrastructure.<br /><u>Data plane:</u> impact on traffic flowing through the device.')

	htmlTOC.append('</ol>')
	htmlTOC.append('</div>')

	htmlFooter.append('</section>')
	htmlFooter.append('</div>')
	htmlFooter.append('<footer>')
	htmlFooter.append('<p id="presentation">')
	htmlFooter.append('RouterDefense is created and maintained by Francois Ropert.')
	htmlFooter.append('<a href="http://www.packetfault.org">http://www.packetfault.org</a>')
	htmlFooter.append('</p>')
	htmlFooter.append('</footer>')
	htmlFooter.append('</body>')
	
	for line in htmlHeader:
		report.write(line)
	report.write('<font size="+1"><b><u>Recommandations found</u></b></font>')
	report.write('<br /><br />')
	for line in htmlSummary:
		report.write(line)
	report.write('<br /><br />')
	report.write('<font size="+1"><b><u>Table of contents</u></b></font>')
	report.write('<br /><br />')
	for line in htmlTOC:
		report.write(line)
	report.write('<br />')
	for line in htmlMPlane:
		report.write(line)
	report.write('<br />')
	for line in htmlCPlane:
		report.write(line)
	report.write('<br />')
	for line in htmlDPlane:
		report.write(line)
	for line in htmlFooter:
		report.write(line)
		
	report.close()
	print "Audit has been saved under the filename: %s " % outputFile 
	return "HTML"
