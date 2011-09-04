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
	htmlTOC.append('\n')
	htmlTOC.append('<ol>')
	htmlTOC.append('\n')

	htmlSummary.append('<div id="summary">')
	htmlSummary.append('\n')
	htmlSummary.append('<table')
	htmlSummary.append('\n')
	htmlSummary.append('<thead><tr><th>Management Plane</th><th>Control Plane</th><th>Data Plane</th></tr></thead>')
	htmlSummary.append('\n')
	htmlSummary.append('<tbody>')
	htmlSummary.append('\n')

	htmlHeader.append('<!DOCTYPE html>')
	htmlHeader.append('\n')
	htmlHeader.append('<head>')
	htmlHeader.append('\n')
	htmlHeader.append('<title>'+ 'RouterDefense ' + date + '</title>')
	htmlHeader.append('\n')
	htmlHeader.append('<link rel="stylesheet" media="all" href="style.css" />')
	htmlHeader.append('\n')
	htmlHeader.append('<script src="http://code.jquery.com/jquery-latest.min.js"></script>')
	htmlHeader.append('\n')
	htmlHeader.append('</head>')
	htmlHeader.append('\n')
	htmlHeader.append('<body>')
	htmlHeader.append('\n')
	htmlHeader.append('<div id="content">')
	htmlHeader.append('\n')
	htmlHeader.append('<header role="banner">')
	htmlHeader.append('\n')
	
	htmlHeader.append('<h1><a href="http://code.google.com/p/routerdefense">Router <span>Defense</span></a></h1>')
	htmlHeader.append('\n')
	htmlHeader.append('<nav role="navigation"><a href=#MPlane>Management Plane</a>  <a href=#CPlane>Control Plane</a>  <a href=#DPlane>Data Plane</a></nav>')
	htmlHeader.append('\n')
	htmlHeader.append('</header>')
	htmlHeader.append('\n')
	htmlHeader.append('<p id="presentation">')
	htmlHeader.append('\n')
	htmlHeader.append('Some of those recommandations could not fit with your environment for any reason from layer 1 to layer 9.')
	htmlHeader.append('\n')
	htmlHeader.append('</p>')
	htmlHeader.append('\n')
	htmlHeader.append('<section class="content">')
	htmlHeader.append('\n')

	htmlHeader.append('<table>')
	htmlHeader.append('\n')
	htmlHeader.append('<thead>')
	htmlHeader.append('\n')
	htmlHeader.append('<tr><th>Hostname</th><th>IOS</th><th>Switching</th><th>Multicast</th><th>QoS</th><th>IPv6</th><th>IPSEC VPN</th></tr>')
	htmlHeader.append('\n')
	htmlHeader.append('</thead>')
	htmlHeader.append('\n')
	htmlHeader.append('<tbody>')
	htmlHeader.append('\n')
	htmlHeader.append('<tr>')
	htmlHeader.append('\n')
	htmlHeader.append('<td>' + genericCfg.hostName + '</td>')
	htmlHeader.append('\n')
	htmlHeader.append('<td>' + genericCfg.iosVersion + '</td>')
	htmlHeader.append('\n')
	htmlHeader.append('<td>' + genericCfg.switchingMethod + '</td>')
	htmlHeader.append('\n')
	htmlHeader.append('<td>' + genericCfg.multicast + '</td>')
	htmlHeader.append('\n')
	htmlHeader.append('<td>' + genericCfg.qos + '</td>')
	htmlHeader.append('\n')
	htmlHeader.append('<td>' + genericCfg.ipv6 + '</td>')
	htmlHeader.append('\n')
	htmlHeader.append('<td>' + genericCfg.ipsec + '</td>')
	htmlHeader.append('\n')
	htmlHeader.append('</tr>')
	htmlHeader.append('\n')
	htmlHeader.append('</tbody>')
	htmlHeader.append('\n')
	htmlHeader.append('</table>')
	htmlHeader.append('\n')
	htmlHeader.append('<br />')
	htmlHeader.append('\n')	

	htmlMPlane.append('<a id="planeTitle" name="MPlane">Management Plane</a><br /><br />')
	vulnIndex = 0
	for name in ManagementPlaneMetrics:
		if name != 'interface':
			for k,v in inspect.getmembers(name):
				if isinstance(v, dict):
					if v['mustBeReported'] == True:
						vulnIndex = vulnIndex + 1
						definition = v['definition'].strip()
						threatInfo = v['threatInfo'].strip()
						howtofix = v['howtofix'].split('\n')
						fixImpact = v['fixImpact'].strip()
						cvss = v['cvss'].strip()
						htmlMPlane.append('\n')
						htmlMPlane.append('<table id="namedef">')
						htmlMPlane.append('\n')
						htmlMPlane.append('<tbody>')
						htmlMPlane.append('\n')
						htmlMPlane.append('<tr>')
						htmlMPlane.append('\n')
						htmlMPlane.append('<a id="planeContent" name="MP'+ str(MPlaneCounter) +'">' + '<td id="name">' + name.longName + '</td>' + '</a>')
						htmlMPlane.append('\n')
						htmlMPlane.append('<td id="definition">' + definition + '</td>')
						htmlMPlane.append('\n')
						if float(cvss) <= 4:
							htmlMPlane.append('<td id="cvssGreen">' + cvss + '/10' + '</td>')
							htmlMPlane.append('\n')
						elif float(cvss) <= 7.9 and cvss >=4.1:
							htmlMPlane.append('<td id="cvssOrange">' + cvss + '/10' + '</td>')
							htmlMPlane.append('\n')
						elif float(cvss) >=8:
							htmlMPlane.append('<td id="cvssRed">' + cvss + '/10' + '</td>')
							htmlMPlane.append('\n')
						htmlMPlane.append('<td id="ToggleButton"><button id='+ str(vulnIndex) +'>Hide/Show</button></td>')
						htmlMPlane.append('</tr>')
						htmlMPlane.append('\n')
						htmlMPlane.append('</tbody>')
						htmlMPlane.append('\n')
						htmlMPlane.append('</table>')
						htmlMPlane.append('\n')
						htmlMPlane.append('<article id="'+ str(vulnIndex) +'"><p>')
						htmlMPlane.append('\n')
						htmlMPlane.append('<p id="threatInfo">Threat information: </p>' + threatInfo + '<br />')
						htmlMPlane.append('\n')
						htmlMPlane.append('<p id="threatInfo">Fix impact: </p>' + fixImpact + '<br />')
						htmlMPlane.append('\n')

						htmlMPlane.append('<table id ="fix">')
						htmlMPlane.append('\n')
						htmlMPlane.append('<thead>')
						htmlMPlane.append('\n')
						htmlMPlane.append('<tr><th id="fix">How to fix</th></tr>')
						htmlMPlane.append('\n')
						htmlMPlane.append('</thead>')
						htmlMPlane.append('\n')
						htmlMPlane.append('<tbody>')
						htmlMPlane.append('\n')
						for index in howtofix:
							htmlMPlane.append('<tr>')
							htmlMPlane.append('\n')
							htmlMPlane.append('<td id="fix">' + index + '</td>')
							htmlMPlane.append('\n')
							htmlMPlane.append('</tr>')
							htmlMPlane.append('\n')
						htmlMPlane.append('</tbody>')
						htmlMPlane.append('\n')
						htmlMPlane.append('</table>')
						htmlMPlane.append('\n')
						htmlMPlane.append('</p></article><br />')
						htmlMPlane.append('\n')
						htmlMPlane.append(' \
						<script> \
						$("button[id=' + str(vulnIndex) + ']").click(function () { \
						$("article[id=' + str(vulnIndex) + ']").toggle("slow"); \
						});     \
						</script> \
						')					

						htmlTOC.append('<li><a href=#MP'+ str(MPlaneCounter) + '>' + name.longName + ': ' + definition + '</a></li>')
						htmlTOC.append('\n')
						MPlaneCounter = MPlaneCounter + 1
							
	htmlCPlane.append('<a id="planeTitle" name="CPlane">Control Plane</a><br /><br />')
	htmlCPlane.append('\n')
	for name in ControlPlaneMetrics:
		if name != 'interface':
			for k,v in inspect.getmembers(name):
				if isinstance(v, dict):
					if v['mustBeReported'] == True:
						vulnIndex = vulnIndex + 1
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
						htmlCPlane.append(' \
						<script> \
						$("button").click(function () { \
						$("article[id=' + str(vulnIndex) + ']").toggle("slow"); \
						});     \
						</script> \
						')						
						htmlCPlane.append('\n')
						htmlCPlane.append('<article id="'+ str(vulnIndex) +'"><p>')
						htmlCPlane.append('\n')						
						htmlCPlane.append('<table id="namedef">')
						htmlCPlane.append('\n')
						htmlCPlane.append('<tbody>')
						htmlCPlane.append('\n')
						htmlCPlane.append('<tr>')
						htmlCPlane.append('\n')
						htmlCPlane.append('<a id="planeContent" name="CP'+ str(CPlaneCounter) +'">' + '<td id="name">' + name.longName + '</td>' + '</a>')
						htmlCPlane.append('\n')
						htmlCPlane.append('<td id="definition">' + definition + '</td>')
						htmlCPlane.append('\n')
						if float(cvss) <= 4:
							htmlCPlane.append('<td id="cvssGreen">' + cvss + '/10' + '</td>')
							htmlCPlane.append('\n')
						elif float(cvss) <= 7.9 and cvss >=4.1:
							htmlCPlane.append('<td id="cvssOrange">' + cvss + '/10' + '</td>')
							htmlCPlane.append('\n')
						elif float(cvss) >=8:
							htmlCPlane.append('<td id="cvssRed">' + cvss + '/10' + '</td>')
							htmlCPlane.append('\n')	
						htmlCPlane.append('<td id="ToggleButton"><button id='+ str(vulnIndex) +'>Hide/Show</button></td>')
						htmlCPlane.append('</tr>')
						htmlCPlane.append('\n')
						htmlCPlane.append('</tbody>')
						htmlCPlane.append('\n')
						htmlCPlane.append('</table>')
						htmlCPlane.append('\n')

						htmlCPlane.append('<p id="threatInfo">Threat information: </p>' + threatInfo + '<br />')
						htmlCPlane.append('\n')
						htmlCPlane.append('<p id="threatInfo">Fix impact: </p>' + fixImpact + '<br />')
						htmlCPlane.append('\n')

						htmlCPlane.append('<table id ="fix">')
						htmlCPlane.append('\n')
						htmlCPlane.append('<thead>')
						htmlCPlane.append('\n')
						htmlCPlane.append('<tr><th id="fix">How to fix</th></tr>')
						htmlCPlane.append('\n')
						htmlCPlane.append('</thead>')
						htmlCPlane.append('\n')
						htmlCPlane.append('<tbody>')
						htmlCPlane.append('\n')
						for index in howtofix:
							htmlCPlane.append('<tr>')
							htmlCPlane.append('\n')
							htmlCPlane.append('<td id="fix">' + index + '</td>')
							htmlCPlane.append('\n')
							htmlCPlane.append('</tr>')
							htmlCPlane.append('\n')
						htmlCPlane.append('</tbody>')
						htmlCPlane.append('\n')
						htmlCPlane.append('</table>')
						htmlCPlane.append('\n')
						htmlCPlane.append('</p></article><br />')
						htmlCPlane.append('\n')
						htmlCPlane.append(' \
						<script> \
						$("button[id=' + str(vulnIndex) + ']").click(function () { \
						$("article[id=' + str(vulnIndex) + ']").toggle("slow"); \
						});     \
						</script> \
						')					

						htmlTOC.append('<li><a href=#CP'+ str(CPlaneCounter) + '>' + name.longName + ': ' + definition + '</a></li>')
						htmlTOC.append('\n')
						CPlaneCounter = CPlaneCounter + 1

	htmlDPlane.append('<a id="planeTitle" name="DPlane">Data Plane</a><br /><br />')
	htmlDPlane.append('\n')	
	for name in DataPlaneMetrics:
		if name != 'interface':
			for k,v in inspect.getmembers(name):
				if isinstance(v, dict):
					if v['mustBeReported'] == True:
						vulnIndex = vulnIndex + 1
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
						htmlDPlane.append(' \
						<script> \
						$("button").click(function () { \
						$("article[id=' + str(vulnIndex) + ']").toggle("slow"); \
						});     \
						</script> \
						')						
						htmlDPlane.append('\n')
						htmlDPlane.append('<article id="'+ str(vulnIndex) +'"><p>')
						htmlDPlane.append('\n')						
						htmlDPlane.append('<table id="namedef">')
						htmlDPlane.append('\n')
						htmlDPlane.append('<tbody>')
						htmlDPlane.append('\n')
						htmlDPlane.append('<tr>')
						htmlDPlane.append('\n')
						htmlDPlane.append('<a id="planeContent" name="DP'+ str(DPlaneCounter) +'">' + '<td id="name">' + name.longName + '</td>' + '</a>')
						htmlDPlane.append('\n')
						htmlDPlane.append('<td id="definition">' + definition + '</td>')
						htmlDPlane.append('\n')
						if float(cvss) <= 4:
							htmlDPlane.append('<td id="cvssGreen">' + cvss + '/10' + '</td>')
							htmlDPlane.append('\n')
						elif float(cvss) <= 7.9 and cvss >=4.1:
							htmlDPlane.append('<td id="cvssOrange">' + cvss + '/10' + '</td>')
							htmlDPlane.append('\n')
						elif float(cvss) >=8:
							htmlDPlane.append('<td id="cvssRed">' + cvss + '/10' + '</td>')
							htmlDPlane.append('\n')						
						htmlDPlane.append('<td id="ToggleButton"><button id='+ str(vulnIndex) +'>Hide/Show</button></td>')
						htmlDPlane.append('</tr>')
						htmlDPlane.append('\n')
						htmlDPlane.append('</tbody>')
						htmlDPlane.append('\n')
						htmlDPlane.append('</table>')
						htmlDPlane.append('\n')

						htmlDPlane.append('<p id="threatInfo">Threat information: </p>' + threatInfo + '<br />')
						htmlDPlane.append('\n')
						htmlDPlane.append('<p id="threatInfo">Fix impact: </p>' + fixImpact + '<br />')
						htmlDPlane.append('\n')

						htmlDPlane.append('<table id ="fix">')
						htmlDPlane.append('\n')
						htmlDPlane.append('<thead>')
						htmlDPlane.append('\n')
						htmlDPlane.append('<tr><th id="fix">How to fix</th></tr>')
						htmlDPlane.append('\n')
						htmlDPlane.append('</thead>')
						htmlDPlane.append('\n')
						htmlDPlane.append('<tbody>')
						htmlDPlane.append('\n')
						for index in howtofix:
							htmlDPlane.append('<tr>')
							htmlDPlane.append('\n')
							htmlDPlane.append('<td id="fix">' + index + '</td>')
							htmlDPlane.append('\n')
							htmlDPlane.append('</tr>')
							htmlDPlane.append('\n')
						htmlDPlane.append('</tbody>')
						htmlDPlane.append('\n')
						htmlDPlane.append('</table>')
						htmlDPlane.append('\n')
						htmlDPlane.append('</p></article><br />')
						htmlDPlane.append('\n')
						htmlDPlane.append(' \
						<script> \
						$("button[id=' + str(vulnIndex) + ']").click(function () { \
						$("article[id=' + str(vulnIndex) + ']").toggle("slow"); \
						});     \
						</script> \
						')					

						htmlTOC.append('<li><a href=#DP'+ str(DPlaneCounter) + '>' + name.longName + ': ' + definition + '</a></li>')
						htmlTOC.append('\n')
						DPlaneCounter = DPlaneCounter + 1


	htmlSummary.append('<tr>')
	htmlSummary.append('\n')
	htmlSummary.append('<td>' + str(MPlaneCounter) + '</td>')
	htmlSummary.append('\n')
	htmlSummary.append('<td>' + str(CPlaneCounter) + '</td>')
	htmlSummary.append('\n')
	htmlSummary.append('<td>' + str(DPlaneCounter) + '</td>')
	htmlSummary.append('\n')	
	htmlSummary.append('</tr>')
	htmlSummary.append('\n')
	
	htmlSummary.append('</tbody>')
	htmlSummary.append('\n')
	htmlSummary.append('</table>')
	htmlSummary.append('\n')
	htmlSummary.append('</div>')
	htmlSummary.append('\n')
	
	htmlSummary.append('<u>Management plane:</u> impact on management.<br /><u>Control plane:</u> impact on infrastructure.<br /><u>Data plane:</u> impact on traffic flowing through the device.')
	htmlSummary.append('\n')

	htmlTOC.append('</ol>')
	htmlTOC.append('\n')
	htmlTOC.append('</div>')
	htmlTOC.append('\n')

	htmlFooter.append('</section>')
	htmlFooter.append('\n')
	htmlFooter.append('</div>')
	htmlFooter.append('\n')
	htmlFooter.append('<footer>')
	htmlFooter.append('\n')
	htmlFooter.append('<p id="presentation">')
	htmlFooter.append('\n')
	htmlFooter.append('RouterDefense is created and maintained by Francois Ropert.')
	htmlFooter.append('\n')
	htmlFooter.append('<a href="http://code.google.com/p/routerdefense">http://code.google.com/p/routerdefense</a>')
	htmlFooter.append('\n')
	htmlFooter.append('</p>')
	htmlFooter.append('\n')
	htmlFooter.append('</footer>')
	htmlFooter.append('\n')
	htmlFooter.append('</body>')
	htmlFooter.append('\n')
	
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
