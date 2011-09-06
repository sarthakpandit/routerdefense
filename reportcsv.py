# -*- coding: iso-8859-1 -*-

def csvReport(outputFile,ManagementPlaneMetrics, ControlPlaneMetrics, DataPlaneMetrics):
	import csv
	import inspect
	import __builtin__	
	File = open(outputFile, 'wt')
	csvWriter = csv.writer(File, delimiter=',', quotechar='\'', quoting=csv.QUOTE_MINIMAL)
	csvWriter.writerow(['Class', 'Definition', 'Threat information', 'How to fix', 'fixImpact', 'CVSS'])
		
	for name in ManagementPlaneMetrics:
		if name != 'interface':
			for k,v in inspect.getmembers(name):
				if isinstance(v, dict):
					if v['mustBeReported'] == True:
						definition = v['definition'].strip()
						threatInfo = v['threatInfo'].strip()
						howtofix = v['howtofix'].strip()
						fixImpact = v['fixImpact'].strip()
						cvss = v['cvss'].strip()
						csvWriter.writerow([name.longName, definition, threatInfo, howtofix, fixImpact, cvss])
	
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
						howtofix = v['howtofix']
						csvWriter.writerow([name.longName, definition, threatInfo, howtofix, fixImpact, cvss])
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

						howtofix = v['howtofix']
						csvWriter.writerow([name.longName, definition, threatInfo, howtofix, fixImpact, cvss])
		
	File.close()
	print "Audit has been saved under the filename: %s " % outputFile 

