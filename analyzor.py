# -*- coding: iso-8859-15 -*-

from common import *
from xml import *
import __builtin__

class genericInfo():	
	def __init__(self):
		self.iosVersion = None
		self.hostName = None
		self.switchingMethod = None
		self.multicast = None
		self.ipv6 = None

def addBasicInfo(lines):
	genericCfg = genericInfo()
	genericCfg.switchingMethod = "Unknown"
	genericCfg.hostName = "Unknown"
	genericCfg.iosVersion = "Unknown"
	
	genericCfg.hostName = searchString(lines, 'hostname').split(' ',2)[1]
	genericCfg.iosVersion = searchString(lines, 'version').split(' ',2)[1]
	
	if searchString(lines, 'ip cef') != None:
		genericCfg.switchingMethod = "CEF"
	if searchString(lines, 'no ip route-cache') != None:
		genericCfg.switchingMethod = "Process switching (CPU)"
	if searchString(lines, 'ip route-cache') != None:
		genericCfg.switchingMethod = "Fast switching"
	if searchString(lines, 'ip multicast-routing') != None:
		genericCfg.multicast = "Enabled"
	else:
		genericCfg.multicast = "Disabled"	
	if ( (searchString(lines, 'mls qos') != None) or (searchRegexString(lines, '^ip rsvp bandwith .*$') != None) ):
		genericCfg.qos = "Enabled"
	else:
		genericCfg.qos = "Disabled"	
	if searchString(lines, 'ipv6 unicast-routing') != None:
		genericCfg.ipv6 = "Enabled"
	else:
		genericCfg.ipv6 = "Disabled"	
	if searchRegexString(lines, '^crypto map \w+$') != None:
		genericCfg.ipsec = "Enabled"
	else:
		genericCfg.ipsec = "Disabled"

	return genericCfg	

def CheckExecTimeout(timeout):
	Compliant = True
	if timeout <= 0:
		Compliant = False
	elif timeout >= 180:
		Compliant = False	 
	return Compliant	

def analyzorCdp(cdpConfiguration, fullConfig, ifaceCfg):
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
		items = searchInXml('serviceCDP')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		cdpConfiguration.cdp['mustBeReported'] = True
		cdpConfiguration.cdp['fixImpact'] = items[0]
		cdpConfiguration.cdp['definition'] = items[1]
		cdpConfiguration.cdp['threatInfo'] = items[2]
		cdpConfiguration.cdp['howtofix'] = items[3]
		cdpConfiguration.cdp['howtofix'] = cdpConfiguration.cdp['howtofix'].strip().replace('[%CdpifsEnabled]', ", ".join(cdpConfiguration.cdp['enabledIfsCdp']), 1)
		cdpConfiguration.cdp['howtofix'] = cdpConfiguration.cdp['howtofix'].strip().replace('[%CdpifsDisabled]', ", ".join(cdpConfiguration.cdp['disabledIfsCdp']), 1)
		cdpConfiguration.cdp['cvss'] = cvssMetrics
				
		return cdpConfiguration.cdp['definition'] + '\n' + cdpConfiguration.cdp['threatInfo'] + '\n\n' + cdpConfiguration.cdp['howtofix'] + '\n'

def analyzorLldp(lldpConfiguration, fullConfig, ifaceCfg):
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
			items = searchInXml('serviceLLDP')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			lldpConfiguration.lldp['mustBeReported'] = True
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
		elif __builtin__.iosVersion == None:
			items = searchInXml('serviceLLDP')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			lldpConfiguration.lldp['mustBeReported'] = True
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

def analyzorConsole(consoleCfg,con0,lines):
	try:	
		con0.execTimeout['cmdInCfg'] = int(searchString(consoleCfg, 'exec-timeout').split(' ',3)[2]) + int(searchString(consoleCfg, 'exec-timeout').split(' ',3)[1]) * 60
	except AttributeError:
		con0.execTimeout['cmdInCfg'] = None

	try:	
		con0.privilegezero['cmdInCfg'] = searchString(consoleCfg, 'privilege 0')
		con0.privilegezero['loginlocal'] = searchString(consoleCfg, 'login local')
	except AttributeError:
		con0.privilegezero['cmdInCfg'] = None

	if con0.privilegezero['cmdInCfg'] == None:
		if con0.privilegezero['loginlocal'] == None:
			items = searchInXml('consoleprivilegezero')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			con0.privilegezero = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),
			"howtofix": (items[3]),
			"upgrade": (items[4]),
			"cvss": (cvssMetrics)}
		else:
			try:
				con0.privilegezero['globalusername'] = searchRegexString(lines, '^username .* privilege 0$')
			except AttributeError:
				pass
			if con0.privilegezero['globalusername'] == None:
				items = searchInXml('consoleprivilegezero')
				cvssMetrics = str(calculateCVSS2Score(items[5]))
				con0.privilegezero = {
				"mustBeReported": True,
				"fixImpact": (items[0]),
				"definition": (items[1]),
				"threatInfo": (items[2]),
				"howtofix": (items[3]),
				"upgrade": (items[4]),
				"cvss": (cvssMetrics)}				
			else:
				con0.privilegezero['mustBeReported'] = False
	else:
		con0.privilegezero['mustBeReported'] = False

	if con0.execTimeout['cmdInCfg'] != None:
		CheckExecTimeout(con0.execTimeout)
		items = searchInXml('consoleExecTimeout')
		if CheckExecTimeout(con0.execTimeout['cmdInCfg']) == False:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			con0.execTimeout = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),
			"howtofix": (items[3]),
			"upgrade": (items[4]),
			"cvss": (cvssMetrics)}
		else:
			con0.execTimeout['mustBeReported'] = False
	else:
		items = searchInXml('consoleExecTimeout')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		con0.execTimeout = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),
		"howtofix": (items[3]),
		"upgrade": (items[4]),
		"cvss": (cvssMetrics)}
	try:
		con0.password = searchString(consoleCfg, 'password').split(' ',2)[2]
	except AttributeError:
		con0.password = None

	toBeReturned = ''
	if con0.privilegezero['mustBeReported'] == True:
		toBeReturned = con0.privilegezero['definition'] + '\n' + con0.privilegezero['threatInfo'] + '\n\n' + con0.privilegezero['howtofix'] + '\n'
	if con0.execTimeout['mustBeReported'] == True:
		toBeReturned = toBeReturned + con0.execTimeout['definition'] + '\n' + con0.execTimeout['threatInfo'] + '\n\n' + con0.execTimeout['howtofix'] + '\n'
	return toBeReturned

def analyzorAux(auxCfg,aux0):
	try:	
		aux0.execTimeout['cmdInCfg'] = int(searchString(auxCfg, 'exec-timeout').split(' ',3)[2]) + int(searchString(auxCfg, 'exec-timeout').split(' ',3)[1]) * 60
	except AttributeError:
		aux0.execTimeout['cmdInCfg'] = None

	try:	
		aux0.transportInput['cmdInCfg'] = searchString(auxCfg, 'transport input none')
	except AttributeError:
		aux0.transportInput['cmdInCfg'] = None

	try:	
		aux0.transportOutput['cmdInCfg'] = searchString(auxCfg, 'transport output none')
	except AttributeError:
		aux0.transportOutput['cmdInCfg'] = None

	try:	
		aux0.noExec['cmdInCfg'] = searchString(auxCfg, 'no exec')
	except AttributeError:
		aux0.noExec['cmdInCfg'] = None

	items = searchInXml('auxExecTimeout')
	if aux0.execTimeout['cmdInCfg'] != None:
		if CheckExecTimeout(aux0.execTimeout) == False:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			aux0.execTimeout = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),
			"howtofix": (items[3]),
			"upgrade": (items[4]),
			"cvss": (cvssMetrics)}
		else:
			aux0.execTimeout['mustBeReported'] = True
	else:
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		aux0.execTimeout = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if aux0.transportInput['cmdInCfg'] != None:
		aux0.transportInput['mustBeReported'] = False
	else:
		items = searchInXml('auxTransportInput')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		aux0.transportInput = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		
	if aux0.transportOutput['cmdInCfg'] != None:
		aux0.transportOutput['mustBeReported'] = False
	else:
		items = searchInXml('auxTransportOutput')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		aux0.transportOutput = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if aux0.noExec['cmdInCfg'] != None:
		aux0.noExec['mustBeReported'] = False
	else:
		items = searchInXml('auxNoExec')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		aux0.noExec = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}
		
	try:
		aux0.password = searchString(auxCfg, 'password').split(' ',2)[2]
	except AttributeError:
		aux0.password = None
	
	toBeReturned = ''
	if aux0.execTimeout['mustBeReported'] == True:
		toBeReturned = aux0.execTimeout['definition'] + '\n' + aux0.execTimeout['threatInfo'] + '\n\n' + aux0.execTimeout['howtofix'] + '\n'
	if aux0.transportInput['mustBeReported'] == True:
		toBeReturned = toBeReturned + aux0.transportInput['definition'] + '\n' + aux0.transportInput['threatInfo'] + '\n\n' + aux0.transportInput['howtofix'] + '\n'
	if aux0.transportOutput['mustBeReported'] == True:
		toBeReturned = toBeReturned + aux0.transportOutput['definition'] + '\n' + aux0.transportOutput['threatInfo'] + '\n\n' + aux0.transportOutput['howtofix'] + '\n'
	if aux0.noExec['mustBeReported'] == True:
		toBeReturned = toBeReturned + aux0.noExec['definition'] + '\n' + aux0.noExec['threatInfo']+ '\n\n' + aux0.noExec['howtofix'] + '\n'

	return toBeReturned

def analyzorVty(vtyCfg,vty):
	try:	
		vty.execTimeout['cmdInCfg'] = int(searchString(vtyCfg, 'exec-timeout').split(' ',3)[2]) + int(searchString(vtyCfg, 'exec-timeout').split(' ',3)[1]) * 60
	except AttributeError:
		vty.execTimeout['cmdInCfg'] = None

	try:	
		vty.transportInput['cmdInCfg'] = searchRegexString(vtyCfg, '^transport input (ssh|none)$')
	except AttributeError:
		vty.transportInput['cmdInCfg'] = None

	try:	
		vty.transportOutput['cmdInCfg'] = searchRegexString(vtyCfg, '^transport output (ssh|none)$')
	except AttributeError:
		vty.transportOutput['cmdInCfg'] = None

	if __builtin__.genericCfg.ipv6 == "Enabled":
		try:	
			vty.IPv6accessClass['cmdInCfg'] = searchRegexString(vtyCfg, '^ipv6 access-class .* in$')
		except AttributeError:
			vty.IPv6accessClass['cmdInCfg'] = None

	if vty.execTimeout['cmdInCfg'] != None:
		items = searchInXml('vtyExecTimeout')
		if CheckExecTimeout(vty.execTimeout) == False:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			vty.execTimeout = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),
			"howtofix": (items[3]).strip().replace('[%vtySessionNumbers]', " ".join(vty.sessionNumbers), 2),
			"upgrade": (items[4]),
			"cvss": (cvssMetrics)}
		else:
			vty.execTimeout['mustBeReported'] = False
	else:
		items = searchInXml('vtyExecTimeout')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		vty.execTimeout = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),
		"howtofix": (items[3]).strip().replace('[%vtySessionNumbers]', " ".join(vty.sessionNumbers), 2),
		"cvss": (cvssMetrics)}

	if vty.transportInput['cmdInCfg'] != None:
		vty.transportInput['mustBeReported'] = False
	else:
		items = searchInXml('vtyTransportInput')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		vty.transportInput = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]).strip().replace('[%vtySessionNumbers]', " ".join(vty.sessionNumbers), 2),
		"cvss": (cvssMetrics)}

	if vty.transportOutput['cmdInCfg'] != None:
		vty.transportOutput['mustBeReported'] = False
	else:
		items = searchInXml('vtyTransportOutput')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		vty.transportOutput = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]).strip().replace('[%vtySessionNumbers]', " ".join(vty.sessionNumbers), 2),
		"cvss": (cvssMetrics)}

	if vty.IPv6accessClass['cmdInCfg'] == None:
		vty.IPv6accessClass['mustBeReported'] = False
	else:
		items = searchInXml('vtyIPv6AccessClass')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		vty.IPv6accessClass = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]).strip().replace('[%vtySessionNumbers]', " ".join(vty.sessionNumbers), 2),
		"cvss": (cvssMetrics)}
		
	try:
		vty.password = searchString(vtyCfg, 'password').split(' ',2)[2]
	except AttributeError:
		vty.password = None

	toBeReturned = ''
	if vty.execTimeout['mustBeReported'] == True:
		toBeReturned = vty.execTimeout['definition'] + '\n' + vty.execTimeout['threatInfo'] + '\n\n' + vty.execTimeout['howtofix'] + '\n'
	if vty.transportInput['mustBeReported'] == True:
		toBeReturned = toBeReturned + vty.transportInput['definition'] + '\n' + vty.transportInput['threatInfo'] + '\n\n' + vty.transportInput['howtofix'] + '\n'
	if vty.transportOutput['mustBeReported'] == True:
		toBeReturned = toBeReturned + vty.transportOutput['definition'] + '\n' + vty.transportOutput['threatInfo'] + '\n\n' + vty.transportOutput['howtofix'] + '\n'
	if vty.IPv6accessClass['mustBeReported'] == True:
		toBeReturned = toBeReturned + vty.IPv6accessClass['definition'] + '\n' + vty.IPv6accessClass['threatInfo'] + '\n\n' + vty.IPv6accessClass['howtofix'] + '\n'

	return toBeReturned

def analyzorBanner(bannerMotd, motd, bannerType):
	toBeReturned = ''
	if bannerType == 0:	
		if len(bannerMotd) == 0:
			items = searchInXml('bannerMOTDconfigured')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			motd.configured = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			if searchString(bannerMotd, __builtin__.genericCfg.hostName) != None :
				items = searchInXml('bannerMOTDhostnameIncluded')
				cvssMetrics = str(calculateCVSS2Score(items[5]))
				motd.routerName = {
				"mustBeReported": True,
				"fixImpact": (items[0]),
				"definition": (items[1]),
				"threatInfo": (items[2]),			
				"howtofix": (items[3]),
				"cvss": (cvssMetrics)}
		if motd.configured['mustBeReported'] == True:
			toBeReturned = motd.configured['definition'] + '\n' + motd.configured['threatInfo'] + '\n\n' + motd.configured['howtofix'] + '\n'
		if motd.routerName['mustBeReported'] == True:
			toBeReturned = toBeReturned + motd.routerName['definition'] + '\n' + motd.routerName['threatInfo'] + '\n\n' + motd.routerName['howtofix'] + '\n'

	if bannerType == 1:	
		if len(bannerMotd) == 0:
			items = searchInXml('bannerLOGINconfigured')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			banLogin.configured = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			if searchString(bannerMotd, __builtin__.genericCfg.hostName) != None :
				items = searchInXml('bannerLOGINhostnameIncluded')
				cvssMetrics = str(calculateCVSS2Score(items[5]))
				banLogin.routerName = {
				"mustBeReported": True,
				"fixImpact": (items[0]),
				"definition": (items[1]),
				"threatInfo": (items[2]),			
				"howtofix": (items[3]),
				"cvss": (cvssMetrics)}
		if banLogin.configured['mustBeReported'] == True:
			toBeReturned = toBeReturned + banLogin.configured['definition'] + '\n' + banLogin.configured['threatInfo'] + '\n\n' + banLogin.configured['howtofix']
		if banLogin.routerName['mustBeReported'] == True:
			toBeReturned = toBeReturned + banLogin.routerName['definition'] + '\n' + banLogin.routerName['threatInfo']+ '\n\n' + banLogin.routerName['howtofix']

	if bannerType == 2:	
		if len(bannerMotd) == 0:
			items = searchInXml('bannerEXECconfigured')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			banExec.configured = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			if searchString(bannerMotd, __builtin__.genericCfg.hostName) != None :
				items = searchInXml('bannerEXEChostnameIncluded')
				cvssMetrics = str(calculateCVSS2Score(items[5]))
				banExec.routerName = {
				"mustBeReported": True,
				"fixImpact": (items[0]),
				"definition": (items[1]),
				"threatInfo": (items[2]),			
				"howtofix": (items[3]),
				"cvss": (cvssMetrics)}

		if banExec.configured['mustBeReported'] == True:
			toBeReturned = toBeReturned + banExec.configured['definition'] + '\n' + banExec.configured['threatInfo'] + '\n\n' + banExec.configured['howtofix'] + '\n'
		if banExec.routerName['mustBeReported'] == True:
			toBeReturned = toBeReturned + banExec.routerName['definition'] + '\n' + banExec.routerName['threatInfo'] + '\n\n' + banExec.routerName['howtofix'] + '\n'

	return toBeReturned

def analyzorServices(lines, services):
	try:
		services.pwdRecovery['cmdInCfg'] = searchString(lines, 'no service password-recovery')
	except AttributeError:
		pass
	
	if services.pwdRecovery['cmdInCfg'] != None:
		# feature already configured
		services.pwdRecovery['mustBeReported'] = False
	else:
		items = searchInXml('pwdRecovery')
		if __builtin__.iosVersion >= 12.314:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			services.pwdRecovery = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			# upgrade to >= 12.314 to get the feature
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			services.pwdRecovery = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[4]),
			"cvss": (cvssMetrics)}

	try:
		services.tcpSmallServers['cmdInCfg'] = searchString(lines, 'no service tcp-small-servers')
	except AttributeError:
		pass

	if services.tcpSmallServers['cmdInCfg'] != None:
		services.tcpSmallServers['mustBeReported'] = False
	else:
		items = searchInXml('tcpSmallServers')
		if __builtin__.iosVersion <= 12.0:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			services.tcpSmallServers = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			services.tcpSmallServers = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),
			"howtofix": (items[4]),
			"cvss": (cvssMetrics)}
	
	try:
		services.udpSmallServers['cmdInCfg'] = searchString(lines, 'no service udp-small-servers')
	except AttributeError:
		pass

	if services.udpSmallServers['cmdInCfg'] != None:
		services.udpSmallServers['mustBeReported'] = False
	else:
		items = searchInXml('udpSmallServers')
		if __builtin__.iosVersion <= 12.0:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			services.udpSmallServers = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			services.udpSmallServers = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),
			"howtofix": (items[4]),
			"cvss": (cvssMetrics)}

	try:
		services.serviceFinger['cmdInCfg'] = searchString(lines, 'no service finger')
	except AttributeError:
		pass

	if services.serviceFinger['cmdInCfg'] != None:
		services.serviceFinger['mustBeReported'] = False
	else:
		items = searchInXml('serviceFinger')
		if __builtin__.iosVersion <= 12.15:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			services.serviceFinger = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			services.serviceFinger = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),
			"howtofix": (items[4]),
			"cvss": (cvssMetrics)}

	try:
		services.serviceBootpServer['cmdInCfg'] = searchString(lines, 'no ip bootp server')
	except AttributeError:
		pass

	if services.serviceBootpServer['cmdInCfg'] != None:
		services.serviceBootpServer['mustBeReported'] = False
	else:
		items = searchInXml('serviceBootpServer')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		services.serviceBootpServer = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	try:
		services.serviceTcpKeepAliveIn['cmdInCfg'] = searchString(lines, 'service tcp-keepalive-in')
	except AttributeError:
		pass

	if services.serviceTcpKeepAliveIn['cmdInCfg'] != None:
		services.serviceTcpKeepAliveIn['mustBeReported'] = False
	else:
		items = searchInXml('serviceTcpKeepAliveIn')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		services.serviceTcpKeepAliveIn = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	try:
		services.serviceTcpKeepAliveOut['cmdInCfg'] = searchString(lines, 'service tcp-keepalive-out')
	except AttributeError:
		pass

	if services.serviceTcpKeepAliveOut['cmdInCfg'] != None:
		services.serviceTcpKeepAliveOut['mustBeReported'] = False
	else:
		items = searchInXml('serviceTcpKeepAliveOut')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		services.serviceTcpKeepAliveOut = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	try:
		services.serviceIpDhcpBootIgnore['cmdInCfg'] = searchString(lines, 'ip dhcp bootp ignore')
	except AttributeError:
		pass

	if services.serviceIpDhcpBootIgnore['cmdInCfg'] != None:
		services.serviceIpDhcpBootIgnore['mustBeReported'] = False
	else:
		items = searchInXml('serviceIpDhcpBootIgnore')
		if __builtin__.iosVersion <= 12.228:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			services.serviceIpDhcpBootIgnore = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			services.serviceIpDhcpBootIgnore = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),
			"howtofix": (items[4]),
			"cvss": (cvssMetrics)}

	try:
		services.serviceDhcp['cmdInCfg'] = searchString(lines, 'no service dhcp')
	except AttributeError:
		pass

	if services.serviceDhcp['cmdInCfg'] != None:
		services.serviceDhcp['mustBeReported'] = False
	else:
		items = searchInXml('serviceDhcp')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		services.serviceDhcp = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	try:
		services.Mop['cmdInCfg'] = searchString(lines, 'no mop enabled')
	except AttributeError:
		pass

	if services.Mop['cmdInCfg'] != None:
		services.Mop['mustBeReported'] = False
	else:
		items = searchInXml('Mop')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		services.Mop = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	try:
		services.ipDomainLookup['cmdInCfg'] = searchString(lines, 'no ip domain-lookup')
	except AttributeError:
		pass

	if services.ipDomainLookup['cmdInCfg'] != None:
		services.ipDomainLookup['mustBeReported'] = False
	else:
		items = searchInXml('ipDomainLookup')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		services.ipDomainLookup = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	try:
		services.servicePad['cmdInCfg'] = searchString(lines, 'no service pad')
	except AttributeError:
		pass

	if services.servicePad['cmdInCfg'] != None:
		services.servicePad['mustBeReported'] = False
	else:
		items = searchInXml('servicePad')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		services.servicePad = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	try:
		services.serviceHttpServer['cmdInCfg'] = searchString(lines, 'no ip http server')
	except AttributeError:
		pass

	if services.serviceHttpServer['cmdInCfg'] != None:
		services.serviceHttpServer['mustBeReported'] = False
	else:
		items = searchInXml('serviceHttpServer')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		services.serviceHttpServer = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	try:
		services.serviceHttpsServer['cmdInCfg'] = searchString(lines, 'no ip http secure-server')
	except AttributeError:
		pass

	if services.serviceHttpsServer['cmdInCfg'] != None:
		services.serviceHttpsServer['mustBeReported'] = False
	else:
		items = searchInXml('serviceHttpsServer')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		services.serviceHttpsServer = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	try:
		services.serviceConfig['cmdInCfg'] = searchString(lines, 'no service config')
	except AttributeError:
		pass

	items = searchInXml('serviceConfig')
	if services.serviceConfig['cmdInCfg'] != None:
		services.serviceConfig['mustBeReported'] = False
	else:
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		services.serviceConfig = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	toBeReturned = ''
	if services.pwdRecovery['mustBeReported'] == True:
		toBeReturned = services.pwdRecovery['definition'] + '\n' + services.pwdRecovery['threatInfo'] + '\n\n' + services.pwdRecovery['howtofix'] + '\n'
	if services.tcpSmallServers['mustBeReported'] == True:
		toBeReturned = toBeReturned + services.tcpSmallServers['definition'] + '\n' + services.tcpSmallServers['threatInfo'] + '\n\n' + services.tcpSmallServers['howtofix'] + '\n'
	if services.udpSmallServers['mustBeReported'] == True:
		toBeReturned = toBeReturned + services.udpSmallServers['definition'] + '\n' + services.udpSmallServers['threatInfo'] + '\n\n' + services.udpSmallServers['howtofix'] + '\n'
	if services.serviceFinger['mustBeReported'] == True:
		toBeReturned = toBeReturned + services.serviceFinger['definition'] + '\n' + services.serviceFinger['threatInfo'] + '\n\n' + services.serviceFinger['howtofix'] + '\n'
	if services.serviceBootpServer['mustBeReported'] == True:
		toBeReturned = toBeReturned + services.serviceBootpServer['definition'] + '\n' + services.serviceBootpServer['threatInfo'] + '\n\n' + services.serviceBootpServer['howtofix'] + '\n'
	if services.serviceTcpKeepAliveIn['mustBeReported'] == True:
		toBeReturned = toBeReturned + services.serviceTcpKeepAliveIn['definition'] + '\n' + services.serviceTcpKeepAliveIn['threatInfo'] + '\n\n' + services.serviceTcpKeepAliveIn['howtofix'] + '\n'
	if services.serviceTcpKeepAliveOut['mustBeReported'] == True:
		toBeReturned = toBeReturned + services.serviceTcpKeepAliveOut['definition'] + '\n' + services.serviceTcpKeepAliveOut['threatInfo'] + '\n\n' + services.serviceTcpKeepAliveOut['howtofix'] + '\n'
	if services.serviceIpDhcpBootIgnore['mustBeReported'] == True:
		toBeReturned = toBeReturned + services.serviceIpDhcpBootIgnore['definition'] + '\n' + services.serviceIpDhcpBootIgnore['threatInfo'] + '\n\n' + services.serviceIpDhcpBootIgnore['howtofix'] + '\n'
	if services.serviceDhcp['mustBeReported'] == True:
		toBeReturned = toBeReturned + services.serviceDhcp['definition'] + '\n' + services.serviceDhcp['threatInfo'] + '\n\n' + services.serviceDhcp['howtofix'] + '\n'
	if services.Mop['mustBeReported'] == True:
		toBeReturned = toBeReturned + services.Mop['definition'] + '\n' + services.Mop['threatInfo'] + '\n\n' + services.Mop['howtofix'] + '\n'
	if services.ipDomainLookup['mustBeReported'] == True:
		toBeReturned = toBeReturned + services.ipDomainLookup['definition'] + '\n' + services.ipDomainLookup['threatInfo'] + '\n\n' + services.ipDomainLookup['howtofix'] + '\n'
	if services.servicePad['mustBeReported'] == True:
		toBeReturned = toBeReturned + services.servicePad['definition'] + '\n' + services.servicePad['threatInfo'] + '\n\n' + services.servicePad['howtofix'] + '\n'
	if services.serviceHttpServer['mustBeReported'] == True:
		toBeReturned = toBeReturned + services.serviceHttpServer['definition'] + '\n' + services.serviceHttpServer['threatInfo'] + '\n\n' + services.serviceHttpServer['howtofix'] + '\n'
	if services.serviceHttpsServer['mustBeReported'] == True:
		toBeReturned = toBeReturned + services.serviceHttpsServer['definition'] + '\n' + services.serviceHttpsServer['threatInfo'] + '\n\n' + services.serviceHttpsServer['howtofix'] + '\n'
	if services.serviceConfig['mustBeReported'] == True:
		toBeReturned = toBeReturned + services.serviceConfig['definition'] + '\n' + services.serviceConfig['threatInfo'] + '\n\n' + services.serviceConfig['howtofix'] + '\n'

	return toBeReturned

def analyzorMemCpu(lines, memCpu):

	try:
		memCpu.schedulerallocate['cmdInCfg'] = searchString(lines, 'scheduler allocate 4000 400')
	except AttributeError:
		pass

	if memCpu.schedulerallocate['cmdInCfg'] == None:
		memCpu.schedulerallocate['mustBeReported'] = True
		
	try:
		memCpu.schedulerinterval['cmdInCfg'] = searchString(lines, 'scheduler interval 500')
	except AttributeError:
		pass

	if memCpu.schedulerinterval['cmdInCfg'] == None:
		memCpu.schedulerinterval['mustBeReported'] = True

	if memCpu.schedulerallocate['mustBeReported'] == True:
		items = searchInXml('schedulerallocate')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		memCpu.schedulerallocate = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if memCpu.schedulerinterval['mustBeReported'] == True:
		items = searchInXml('schedulerinterval')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		memCpu.schedulerinterval = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}


	try:
		memCpu.lowWatermarkProcessor['cmdInCfg'] = searchString(lines, 'memory free low-watermark processor')
	except AttributeError:
		pass

	if memCpu.lowWatermarkProcessor['cmdInCfg'] != None:
		# feature already configured
		memCpu.lowWatermarkProcessor['mustBeReported'] = False
	else:
		items = searchInXml('lowWatermarkProcessor')
		if __builtin__.iosVersion >= 12.34:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			memCpu.lowWatermarkProcessor = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			# upgrade to >= 12.34 to get the feature
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			memCpu.lowWatermarkProcessor = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[4]),
			"cvss": (cvssMetrics)}

	try:
		memCpu.lowWatermarkIo['cmdInCfg'] = searchString(lines, 'memory free low-watermark io')
	except AttributeError:
		pass
	if memCpu.lowWatermarkIo['cmdInCfg'] != None:
		# feature already configured
		memCpu.lowWatermarkIo['mustBeReported'] = False
	else:
		items = searchInXml('lowWatermarkIo')
		if __builtin__.iosVersion >= 12.34:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			memCpu.lowWatermarkIo = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			# upgrade to >= 12.34 to get the feature
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			memCpu.lowWatermarkIo = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[4]),
			"cvss": (cvssMetrics)}

	try:
		memCpu.memReserveCritical['cmdInCfg'] = searchString(lines, 'memory reserve critical')
	except AttributeError:
		pass
	if memCpu.memReserveCritical['cmdInCfg'] != None:
		# feature already configured
		memCpu.memReserveCritical['mustBeReported'] = False
	else:
		items = searchInXml('memReserveCritical')
		if __builtin__.iosVersion >= 12.34:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			memCpu.memReserveCritical = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			# upgrade to >= 12.34 to get the feature
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			memCpu.memReserveCritical = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[4]),
			"cvss": (cvssMetrics)}

	try:
		memCpu.memReserveConsole['cmdInCfg'] = searchString(lines, 'memory reserve console')
	except AttributeError:
		pass
	if memCpu.memReserveConsole['cmdInCfg'] != None:
		# feature already configured
		memCpu.memReserveConsole['mustBeReported'] = False
	else:
		items = searchInXml('memReserveConsole')
		if __builtin__.iosVersion >= 12.34:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			memCpu.memReserveConsole = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			# upgrade to >= 12.34 to get the feature
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			memCpu.memReserveConsole = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[4]),
			"cvss": (cvssMetrics)}


	try:
		memCpu.memIgnoreOverflowIo['cmdInCfg'] = searchString(lines, 'exception memory ignore overflow io')
	except AttributeError:
		pass
	if memCpu.memIgnoreOverflowIo['cmdInCfg'] != None:
		# feature already configured
		memCpu.memIgnoreOverflowIo['mustBeReported'] = False
	else:
		items = searchInXml('memOverflowIo')
		if __builtin__.iosVersion >= 12.38:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			memCpu.memIgnoreOverflowIo = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			# upgrade to >= 12.38 to get the feature
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			memCpu.memIgnoreOverflowIo = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[4]),
			"cvss": (cvssMetrics)}
				
	try:
		memCpu.memIgnoreOverflowCpu['cmdInCfg'] = searchString(lines, 'exception memory ignore overflow processor')
	except AttributeError:
		pass
	if memCpu.memIgnoreOverflowCpu['cmdInCfg'] != None:
		# feature already configured
		memCpu.memIgnoreOverflowCpu['mustBeReported'] = False
	else:
		items = searchInXml('memOverflowProcessor')
		if __builtin__.iosVersion >= 12.38:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			memCpu.memIgnoreOverflowCpu = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			# upgrade to >= 12.38 to get the feature
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			memCpu.memIgnoreOverflowCpu = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[4]),
			"cvss": (cvssMetrics)}

				
	try:
		memCpu.cpuThresholdNotice['cmdSnmpServerTraps'] = searchString(lines, 'snmp-server enable traps cpu threshold')
	except AttributeError:
		pass
	try:
		memCpu.cpuThresholdNotice['cmdSnmpServerHost'] = searchRegexString(lines, 'snmp-server host .* .* cpu')
	except AttributeError:
		pass
	try:
		memCpu.cpuThresholdNotice['cmdCpuThreshold'] = searchRegexString(lines, 'process cpu threshold type .* rising .* interval')
	except AttributeError:
		pass
	try:
		memCpu.cpuThresholdNotice['cmdCpuStats'] = searchRegexString(lines, 'process cpu statistics limit entry-percentage .*')
	except AttributeError:
		pass

	if ((memCpu.cpuThresholdNotice['cmdSnmpServerTraps'] != None) and (memCpu.cpuThresholdNotice['cmdSnmpServerHost'] != None) and (memCpu.cpuThresholdNotice['cmdCpuThreshold'] != None) and (memCpu.cpuThresholdNotice['cmdCpuStats'] != None) ):
		memCpu.cpuThresholdNotice['mustBeReported'] = False
	else:
		items = searchInXml('cpuThresholdNotification')
		if __builtin__.iosVersion >= 12.34:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			memCpu.cpuThresholdNotice = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			# upgrade to >= 12.34 to get the feature
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			memCpu.cpuThresholdNotice = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[4]),
			"cvss": (cvssMetrics)}

	toBeReturned = ''
	if memCpu.schedulerallocate['mustBeReported'] == True:
		toBeReturned = toBeReturned + memCpu.schedulerallocate['definition'] + '\n' + memCpu.schedulerallocate['threatInfo'] + '\n\n' + memCpu.schedulerallocate['howtofix'] + '\n'
	if memCpu.schedulerinterval['mustBeReported'] == True:
		toBeReturned = toBeReturned + memCpu.schedulerinterval['definition'] + '\n' + memCpu.schedulerinterval['threatInfo'] + '\n\n' + memCpu.schedulerinterval['howtofix'] + '\n'
	if memCpu.lowWatermarkProcessor['mustBeReported'] == True:
		toBeReturned = memCpu.lowWatermarkProcessor['definition'] + '\n' + memCpu.lowWatermarkProcessor['threatInfo'] + '\n\n' + memCpu.lowWatermarkProcessor['howtofix'] + '\n'
	if memCpu.lowWatermarkIo['mustBeReported'] == True:
		toBeReturned = toBeReturned + memCpu.lowWatermarkIo['definition'] + '\n' + memCpu.lowWatermarkIo['threatInfo'] + '\n\n' + memCpu.lowWatermarkIo['howtofix'] + '\n'
	if memCpu.memReserveCritical['mustBeReported'] == True:
		toBeReturned = toBeReturned + memCpu.memReserveCritical['definition'] + '\n' + memCpu.memReserveCritical['threatInfo'] + '\n\n' + memCpu.memReserveCritical['howtofix'] + '\n'
	if memCpu.memReserveConsole['mustBeReported'] == True:
		toBeReturned = toBeReturned + memCpu.memReserveConsole['definition'] + '\n' + memCpu.memReserveConsole['threatInfo'] + '\n\n' + memCpu.memReserveConsole['howtofix'] + '\n'
	if memCpu.memIgnoreOverflowIo['mustBeReported'] == True:
		toBeReturned = toBeReturned + memCpu.memIgnoreOverflowIo['definition'] + '\n' + memCpu.memIgnoreOverflowIo['threatInfo'] + '\n\n' + memCpu.memIgnoreOverflowIo['howtofix'] + '\n'
	if memCpu.memIgnoreOverflowCpu['mustBeReported'] == True:
		toBeReturned = toBeReturned + memCpu.memIgnoreOverflowCpu['definition'] + '\n' + memCpu.memIgnoreOverflowCpu['threatInfo'] + '\n\n' + memCpu.memIgnoreOverflowCpu['howtofix'] + '\n'
	if memCpu.cpuThresholdNotice['mustBeReported'] == True:
		toBeReturned = toBeReturned + memCpu.cpuThresholdNotice['definition'] + '\n' + memCpu.cpuThresholdNotice['threatInfo'] + '\n\n' + memCpu.cpuThresholdNotice['howtofix'] + '\n'

	return toBeReturned
					
def analyzorCrashinfo(lines, crashinfo):
	try:
		crashinfo.crashinfoMaxFiles['cmdInCfg'] = searchString(lines, 'exception crashinfo maximum files')
	except AttributeError:
		pass
	if crashinfo.crashinfoMaxFiles['cmdInCfg'] != None:
		# feature already configured
		crashinfo.crashinfoMaxFiles['mustBeReported'] = False
	else:
		items = searchInXml('ExceptionMaximumFiles')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		crashinfo.crashinfoMaxFiles = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	toBeReturned = ''
	if crashinfo.crashinfoMaxFiles['mustBeReported'] == True:
		toBeReturned = crashinfo.crashinfoMaxFiles['definition'] + '\n' + crashinfo.crashinfoMaxFiles['threatInfo'] + '\n\n' + crashinfo.crashinfoMaxFiles['howtofix'] + '\n'
	return toBeReturned

def analyzorMPP(lines, vtyList, vtyCfg, mpp):

	if len(vtyList) == 0:
		# if all vty are removed
		mpp.managementInterface['mustBeReported'] = False
		mpp.sshServer['mustBeReported'] = False
		mpp.scpServer['mustBeReported'] = False
		return
	
	for i in range(0, len(vtyCfg)):
		for k in range (0, len(vtyCfg[i])):
			if searchString(vtyCfg[i][k], 'transport input none') != None:
				mpp.managementInterface['mustBeReported'] = False
				mpp.sshServer['mustBeReported'] = False
				mpp.scpServer['mustBeReported'] = False
				return				
	if __builtin__.deviceType == 'router':
		try:
			mpp.managementInterface['cpHostCfg'] = searchString(lines, 'control-plane host')
		except AttributeError:
			pass
		try:
			mpp.managementInterface['mgmtIfaceCfg'] = searchRegexString(lines, 'management-interface .* allow .*')
		except AttributeError:
			pass

		if mpp.managementInterface['cpHostCfg'] != None:
			if mpp.managementInterface['mgmtIfaceCfg'] != None:
				mpp.managementInterface['mustBeReported'] = False
			else:
				if __builtin__.iosVersion >= 12.46:	
					items = searchInXml('ManagementPlaneProtection')
					cvssMetrics = str(calculateCVSS2Score(items[5]))
					mpp.managementInterface = {
					"mustBeReported": True,
					"fixImpact": (items[0]),
					"definition": (items[1]),
					"threatInfo": (items[2]),			
					"howtofix": (items[3]),
					"cvss": (cvssMetrics)}
				else:
					items = searchInXml('ManagementPlaneProtection')
					cvssMetrics = str(calculateCVSS2Score(items[5]))
					mpp.managementInterface = {
					"mustBeReported": True,
					"fixImpact": (items[0]),
					"definition": (items[1]),
					"threatInfo": (items[2]),			
					"howtofix": (items[4]),
					"cvss": (cvssMetrics)}
		else:
			if __builtin__.iosVersion >= 12.46:	
				items = searchInXml('ManagementPlaneProtection')
				cvssMetrics = str(calculateCVSS2Score(items[5]))
				mpp.managementInterface = {
				"mustBeReported": True,
				"fixImpact": (items[0]),
				"definition": (items[1]),
				"threatInfo": (items[2]),			
				"howtofix": (items[3]),
				"cvss": (cvssMetrics)}
			else:
				items = searchInXml('ManagementPlaneProtection')
				cvssMetrics = str(calculateCVSS2Score(items[5]))
				mpp.managementInterface = {
				"mustBeReported": True,
				"fixImpact": (items[0]),
				"definition": (items[1]),
				"threatInfo": (items[2]),			
				"howtofix": (items[4]),
				"cvss": (cvssMetrics)}
				
	try:
		mpp.sshServerTimeout['timeout'] = searchString(lines, 'ip ssh time-out')
	except AttributeError:
		pass
	try:
		mpp.sshServerAuthRetries['authRetries'] = searchString(lines, 'ip ssh authentication-retries')
	except AttributeError:
		pass
	try:
		mpp.sshServerSourceInterface['sourceInterface'] = searchString(lines, 'ip ssh source-interface')
	except AttributeError:
		pass

	if mpp.sshServerTimeout['timeout'] == None:
		items = searchInXml('sshServerTimeout')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		mpp.sshServerTimeout = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}
	else:
		mpp.sshServerTimeout['mustBeReported'] = False

	if mpp.sshServerAuthRetries['authRetries'] == None:
		items = searchInXml('sshServerAuthretries')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		mpp.sshServerAuthRetries = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}
	else:
		mpp.sshServerAuthRetries['mustBeReported'] = False
		
	if mpp.sshServerSourceInterface['sourceInterface'] == None:
		items = searchInXml('sshServerSourceIf')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		mpp.sshServerSourceInterface = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}
	else:
		mpp.sshServerSourceInterface['mustBeReported'] = False		

	try:
		mpp.scpServer['cmdIncfg'] = searchString(lines, 'ip scp server enable')
	except AttributeError:
		pass

	if mpp.scpServer['cmdIncfg'] == None:
		items = searchInXml('sshSCPServer')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		mpp.scpServer = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}
	else:
		mpp.scpServer['mustBeReported'] = False		
	
	try:
		mpp.httpSecureServer['cmdIncfg'] = searchString(lines, 'ip http server')
	except AttributeError:
		pass

	if mpp.httpSecureServer['cmdIncfg'] != None:
		items = searchInXml('HTTPServer')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		mpp.httpSecureServer = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}
	else:
		mpp.httpSecureServer['mustBeReported'] = False		

	try:
		mpp.loginbruteforce['blockfor'] = searchString(lines, 'login block-for')
	except AttributeError:
		pass
	try:
		mpp.loginbruteforce['delay'] = searchString(lines, 'login delay')
	except AttributeError:
		pass
	try:
		mpp.loginbruteforce['quietacl'] = searchString(lines, 'login quiet access-class')
	except AttributeError:
		pass
	try:
		mpp.loginbruteforce['faillog'] = searchString(lines, 'login on-failure log every')
	except AttributeError:
		pass
	try:
		mpp.loginbruteforce['successlog'] = searchString(lines, 'login on-success log every')
	except AttributeError:
		pass
	loginbruteforceCount = 0
	if mpp.loginbruteforce['blockfor'] != None: 
		loginbruteforceCount = loginbruteforceCount + 1 
	if mpp.loginbruteforce['delay'] != None: 
		loginbruteforceCount = loginbruteforceCount + 1
	if mpp.loginbruteforce['quietacl'] != None: 
		loginbruteforceCount = loginbruteforceCount + 1
	if mpp.loginbruteforce['faillog'] != None: 
		loginbruteforceCount = loginbruteforceCount + 1
	if mpp.loginbruteforce['successlog'] != None: 
		loginbruteforceCount = loginbruteforceCount + 1				
					
	if loginbruteforceCount < 5:
		if __builtin__.iosVersion >= 12.34:
			items = searchInXml('loginBruteforce')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			mpp.loginbruteforce = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			# upgrade to >= 12.3.4 to get the feature
			items = searchInXml('loginBruteforce')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			mpp.loginbruteforce = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[4]),
			"cvss": (cvssMetrics)}
	else:
		mpp.loginbruteforce['mustBeReported'] = False		

	toBeReturned = ''
	if mpp.managementInterface['mustBeReported'] == True:
		toBeReturned = mpp.managementInterface['definition'] + '\n' + mpp.managementInterface['threatInfo'] + '\n\n' + mpp.managementInterface['howtofix'] + '\n'
	if mpp.sshServerTimeout['mustBeReported'] == True:
		toBeReturned = toBeReturned + mpp.sshServerTimeout['definition'] + '\n' + mpp.sshServerTimeout['threatInfo'] + '\n\n' + mpp.sshServerTimeout['howtofix'] + '\n'
	if mpp.sshServerAuthRetries['mustBeReported'] == True:
		toBeReturned = toBeReturned + mpp.sshServerAuthRetries['definition'] + '\n' + mpp.sshServerAuthRetries['threatInfo'] + '\n\n' + mpp.sshServerAuthRetries['howtofix'] + '\n'
	if mpp.sshServerSourceInterface['mustBeReported'] == True:
		toBeReturned = toBeReturned + mpp.sshServerSourceInterface['definition'] + '\n' + mpp.sshServerSourceInterface['threatInfo'] + '\n\n' + mpp.sshServerSourceInterface['howtofix'] + '\n'
	if mpp.scpServer['mustBeReported'] == True:
		toBeReturned = toBeReturned + mpp.scpServer['definition'] + '\n' + mpp.scpServer['threatInfo'] + '\n\n' + mpp.scpServer['howtofix'] + '\n'
	if mpp.httpSecureServer['mustBeReported'] == True:
		toBeReturned = toBeReturned + mpp.httpSecureServer['definition'] + '\n' + mpp.httpSecureServer['threatInfo'] + '\n\n' + mpp.httpSecureServer['howtofix'] + '\n'
	if mpp.loginbruteforce['mustBeReported'] == True:
		toBeReturned = toBeReturned + mpp.loginbruteforce['definition'] + '\n' + mpp.loginbruteforce['threatInfo'] + '\n\n' + mpp.loginbruteforce['howtofix'] + '\n'

	return toBeReturned
		
def analyzorPasswordManagement(lines, pwdManagement):
	try:
		pwdManagement.enableSecret['cmdInCfg'] = searchString(lines, 'enable secret')
	except AttributeError:
		pass
	if pwdManagement.enableSecret['cmdInCfg'] != None:
		# feature already configured
		pwdManagement.enableSecret['mustBeReported'] = False
	else:
		items = searchInXml('enableSecret')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		pwdManagement.enableSecret = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}
	
	try:
		pwdManagement.svcPwdEncryption['cmdInCfg'] = searchRegexString(lines, '^service password-encryption')
	except AttributeError:
		pass
	if pwdManagement.svcPwdEncryption['cmdInCfg'] != None:
		# feature already configured
		pwdManagement.svcPwdEncryption['mustBeReported'] = False
	else:
		items = searchInXml('servicePasswordEncryption')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		pwdManagement.svcPwdEncryption = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	try:
		pwdManagement.usernameSecret['cmdInCfg'] = searchRegexString(lines, '^username .* password .*')
	except AttributeError:
		pass
	if pwdManagement.usernameSecret['cmdInCfg'] == None:
		# feature already configured or not used
		pwdManagement.usernameSecret['mustBeReported'] = False
	else:
		items = searchInXml('usernameSecret')
		if __builtin__.iosVersion >= 12.28:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			pwdManagement.usernameSecret = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			pwdManagement.usernameSecret = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[4]),
			"cvss": (cvssMetrics)}			

	try:
		pwdManagement.retryLockout['aaaNewModel'] = searchRegexString(lines, '^aaa new-model')
	except AttributeError:
		pass
	try:
		pwdManagement.retryLockout['usernames'] = searchRegexString(lines, '^username .*')
	except AttributeError:
		pass
	try:
		pwdManagement.retryLockout['maxFail'] = searchString(lines, 'aaa local authentication attempts max-fail')
	except AttributeError:
		pass
	try:
		pwdManagement.retryLockout['aaaAuthLoginLocal'] = searchRegexString(lines, 'aaa authentication login default (local|.*) ?local')
	except AttributeError:
		pass	

	if ((pwdManagement.retryLockout['aaaNewModel'] != None) and (pwdManagement.retryLockout['maxFail'] != None) and (pwdManagement.retryLockout['aaaAuthLoginLocal'] != None) ):
		pwdManagement.retryLockout['mustBeReported'] = False
	elif pwdManagement.retryLockout['usernames'] == None:
		pwdManagement.retryLockout['mustBeReported'] = False
	else:
		items = searchInXml('retryLockout')
		if __builtin__.iosVersion >= 12.314:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			pwdManagement.retryLockout = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			# upgrade to >= 12.314 to get the feature
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			pwdManagement.retryLockout = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[4]),
			"cvss": (cvssMetrics)}

	toBeReturned = ''
	if pwdManagement.enableSecret['mustBeReported'] == True:
		toBeReturned = pwdManagement.enableSecret['definition'] + '\n' + pwdManagement.enableSecret['threatInfo'] + '\n\n' + pwdManagement.enableSecret['howtofix'] + '\n'
	if pwdManagement.svcPwdEncryption['mustBeReported'] == True:
		toBeReturned = toBeReturned + pwdManagement.svcPwdEncryption['definition'] + '\n' + pwdManagement.svcPwdEncryption['threatInfo'] + '\n\n' + pwdManagement.svcPwdEncryption['howtofix'] + '\n'
	if pwdManagement.usernameSecret['mustBeReported'] == True:
		toBeReturned = toBeReturned + pwdManagement.usernameSecret['definition'] + '\n' + pwdManagement.usernameSecret['threatInfo'] + '\n\n' + pwdManagement.usernameSecret['howtofix'] + '\n'
	if pwdManagement.retryLockout['mustBeReported'] == True:
		toBeReturned = toBeReturned + pwdManagement.retryLockout['definition'] + '\n' + pwdManagement.retryLockout['threatInfo'] + '\n\n' + pwdManagement.retryLockout['howtofix'] + '\n'

	return toBeReturned

def analyzorTacacs(lines, tacacs, mode):
	toBeReturned = ''
	try:
		tacacs.aaaNewModel['cmdInCfg'] = searchString(lines, 'aaa new-model')
	except AttributeError:
		pass

	if mode == 'Authentication':
		
		try:
			tacacs.authTacacs['cmdInCfg'] = searchRegexString(lines, 'aaa authentication login default (group tacacs\+|.*) ?tacacs\+')
		except AttributeError:
			pass	

		try:
			tacacs.authFallback['cmdInCfg'] = searchRegexString(lines, 'aaa authentication login default (group tacacs\+|.*) (enable|local)')
		except AttributeError:
			pass
	
		if tacacs.aaaNewModel['cmdInCfg'] == None:
			items = searchInXml('aaaNewModel')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			tacacs.aaaNewmodel = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			tacacs.aaaNewModel['mustBeReported'] = False
	
		if tacacs.authTacacs['cmdInCfg'] == None:
			items = searchInXml('aaaAuthTacacs')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			tacacs.authTacacs = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			tacacs.authTacacs['mustBeReported'] = False
				
		if tacacs.authFallback['cmdInCfg'] == None:
			items = searchInXml('aaaAuthTacacsFallback')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			tacacs.authFallback = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}			
		else:
			tacacs.authFallback['mustBeReported'] = False
			
	elif mode == 'Authorization':

		try:
			tacacs.authExec['cmdInCfg'] = searchString(lines, 'aaa authorization exec default group tacacs none')
		except AttributeError:
			pass
		
		try:
			tacacs.level0['cmdInCfg'] = searchString(lines, 'aaa authorization commands 0 default group tacacs none')
		except AttributeError:
			pass
		
		try:
			tacacs.level1['cmdInCfg'] = searchString(lines, 'aaa authorization commands 1 default group tacacs none')
		except AttributeError:
			pass			

		try:
			tacacs.level15['cmdInCfg'] = searchString(lines, 'aaa authorization commands 15 default group tacacs none')
		except AttributeError:
			pass

		if tacacs.authExec['cmdInCfg'] == None:
			items = searchInXml('aaaAuthTacacsExec')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			tacacs.authExec = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}			
		else:
			tacacs.authExec['mustBeReported'] = False		

		if tacacs.level0['cmdInCfg'] == None:
			items = searchInXml('aaaAuthTacacsLevel0')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			tacacs.level0 = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}			
		else:
			tacacs.level0['mustBeReported'] = False
				
		if tacacs.level1['cmdInCfg'] == None:
			items = searchInXml('aaaAuthTacacsLevel1')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			tacacs.level1 = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}			
		else:
			tacacs.level1['mustBeReported'] = False	
				
		if tacacs.level15['cmdInCfg'] == None:
			items = searchInXml('aaaAuthTacacsLevel15')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			tacacs.level15 = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}			
		else:
			tacacs.level15['mustBeReported'] = False		
				
	elif mode == 'Accounting':

		try:
			tacacs.authAccounting['cmdInCfg'] = searchString(lines, 'aaa accounting exec default start-stop group tacacs')
		except AttributeError:
			pass
		
		try:
			tacacs.level0['cmdInCfg'] = searchString(lines, 'aaa accounting commands 0 default start-stop group tacacs')
		except AttributeError:
			pass
		
		try:
			tacacs.level1['cmdInCfg'] = searchString(lines, 'aaa accounting commands 1 default start-stop group tacacs')
		except AttributeError:
			pass			

		try:
			tacacs.level15['cmdInCfg'] = searchString(lines, 'aaa accounting commands 15 default start-stop group tacacs')
		except AttributeError:
			pass

		if tacacs.authAccounting['cmdInCfg'] == None:
			items = searchInXml('aaaAccountingTacacsExec')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			tacacs.authAccounting = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}			
		else:
			tacacs.authAccounting['mustBeReported'] = False		

		if tacacs.level0['cmdInCfg'] == None:
			items = searchInXml('aaaAccountingTacacsLevel0')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			tacacs.level0 = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}			
		else:
			tacacs.level0['mustBeReported'] = False
			
		if tacacs.level1['cmdInCfg'] == None:
			items = searchInXml('aaaAccountingTacacsLevel1')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			tacacs.level1 = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}			
		else:
			tacacs.level1['mustBeReported'] = False	
			
		if tacacs.level15['cmdInCfg'] == None:
			items = searchInXml('aaaAccountingTacacsLevel15')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			tacacs.level15 = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}			
		else:
			tacacs.level15['mustBeReported'] = False		

	elif mode == 'RedundantAAA':
		
		countServers = 0
		for line in lines:
			if searchString(lines, 'tacacs-server host') != None:
				countServers = countServers +1
		
		if countServers >= 2:
			tacacs.redundant['mustBeReported'] = False
		else:
			items = searchInXml('aaaTacacsRedundant')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			tacacs.redundant = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}

	if mode == 'RedundantAAA':		
		if tacacs.redundant['mustBeReported'] == True:
			toBeReturned = tacacs.redundant['definition'] + '\n' + tacacs.redundant['threatInfo'] + '\n\n' + tacacs.redundant['howtofix'] + '\n'
	elif mode == 'Authentication':
		if tacacs.aaaNewModel['mustBeReported'] == True:
			toBeReturned = toBeReturned + tacacs.aaaNewModel['definition'] + '\n' + tacacs.aaaNewModel['threatInfo'] + '\n\n' + tacacs.aaaNewModel['howtofix'] + '\n'
		if tacacs.authTacacs['mustBeReported'] == True:
			toBeReturned = toBeReturned + tacacs.authTacacs['definition'] + '\n' + tacacs.authTacacs['threatInfo'] + '\n\n' + tacacs.authTacacs['howtofix'] + '\n'
		if tacacs.authFallback['mustBeReported'] == True:
			toBeReturned = toBeReturned + tacacs.authFallback['definition'] + '\n' + tacacs.authFallback['threatInfo'] + '\n\n' + tacacs.authFallback['howtofix'] + '\n'
	elif mode == 'Authorization':
		if tacacs.authExec['mustBeReported'] == True:
			toBeReturned = toBeReturned + tacacs.authExec['definition'] + '\n' + tacacs.authExec['threatInfo'] + '\n\n' + tacacs.authExec['howtofix'] + '\n'
		if tacacs.level0['mustBeReported'] == True:
			toBeReturned = toBeReturned + tacacs.level0['definition'] + '\n' + tacacs.level0['threatInfo'] + '\n\n' + tacacs.level0['howtofix'] + '\n'
		if tacacs.level1['mustBeReported'] == True:
			toBeReturned = toBeReturned + tacacs.level1['definition'] + '\n' + tacacs.level1['threatInfo'] + '\n\n' + tacacs.level1['howtofix'] + '\n'
		if tacacs.level15['mustBeReported'] == True:
			toBeReturned = toBeReturned + tacacs.level15['definition'] + '\n' + tacacs.level15['threatInfo'] + '\n\n' + tacacs.level15['howtofix'] + '\n'
	elif mode == 'Accounting':	
		if tacacs.authAccounting['mustBeReported'] == True:
			toBeReturned = toBeReturned + tacacs.authAccounting['definition'] + '\n' + tacacs.authAccounting['threatInfo'] + '\n\n' + tacacs.authAccounting['howtofix'] + '\n'
		if tacacs.level0['mustBeReported'] == True:
			toBeReturned = toBeReturned + tacacs.level0['definition'] + '\n' + tacacs.level0['threatInfo'] + '\n\n' + tacacs.level0['howtofix'] + '\n'
		if tacacs.level1['mustBeReported'] == True:
			toBeReturned = toBeReturned + tacacs.level1['definition'] + '\n' + tacacs.level1['threatInfo'] + '\n\n' + tacacs.level1['howtofix'] + '\n'
		if tacacs.level15['mustBeReported'] == True:
			toBeReturned = toBeReturned + tacacs.level15['definition'] + '\n' + tacacs.level15['threatInfo'] + '\n\n' + tacacs.level15['howtofix'] + '\n'

	return toBeReturned
			
def analyzorSNMP(lines, snmp):
	try:
		snmp.ROcommunity['cmdInCfg'] = searchRegexString(lines, 'snmp-server community .* (RO|ro)')
	except AttributeError:
		pass
	if snmp.ROcommunity['cmdInCfg'] == None:
		# feature not configured
		snmp.ROcommunity['mustBeReported'] = False
		snmp.ROcommunityACL['mustBeReported'] = False
	else:
		SNMPcommunity = snmp.ROcommunity['cmdInCfg'].split(' ')
		ROsecure = SNMPsecureCommunity(SNMPcommunity[2])
		if ROsecure == False:
			items = searchInXml('snmpROcommunityHardened')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			snmp.ROcommunity = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3].strip().replace('[%ManagementSubnet]', __builtin__.IPv4trustedNetManagementServers[0][0], 1)),
			"howtofix": (items[3].strip().replace('[%ManagementWildcardMask]', __builtin__.IPv4trustedNetManagementServers[0][3], 1)),
			"cvss": (cvssMetrics)}
		try:
			snmp.ROcommunityACL['cmdInCfg'] = searchRegexString(lines, 'snmp-server community .* (RO|ro) \d')
		except AttributeError:
			pass
		
		if snmp.ROcommunityACL['cmdInCfg'] == None:
			items = searchInXml('snmpROcommunityHardenedACL')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			snmp.ROcommunityACL = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3].strip().replace('[%ManagementSubnet]', __builtin__.IPv4trustedNetManagementServers[0][0], 1)),
			"howtofix": (items[3].strip().replace('[%ManagementWildcardMask]', __builtin__.IPv4trustedNetManagementServers[0][3], 1)),
			"cvss": (cvssMetrics)}
		else:
			accessListNumber = snmp.ROcommunityACL['cmdInCfg'].split(' ')[4]
			if checkStdACL(lines, accessListNumber) == True:
				snmp.ROcommunityACL['mustBeReported'] = False
			else:
				items = searchInXml('snmpROcommunityHardenedACL')
				cvssMetrics = str(calculateCVSS2Score(items[5]))
				snmp.ROcommunityACL = {
				"mustBeReported": True,
				"fixImpact": (items[0]),
				"definition": (items[1]),
				"threatInfo": (items[2]),			
				"howtofix": (items[3].strip().replace('[%ManagementSubnet]', __builtin__.IPv4trustedNetManagementServers[0][0], 1)),
				"howtofix": (items[3].strip().replace('[%ManagementWildcardMask]', __builtin__.IPv4trustedNetManagementServers[0][3], 1)),
				"cvss": (cvssMetrics)}

	try:
		snmp.RWcommunity['cmdInCfg'] = searchRegexString(lines, 'snmp-server community .* (RW|rw)')
	except AttributeError:
		pass
	if snmp.RWcommunity['cmdInCfg'] == None:
		# feature not configured
		snmp.RWcommunity['mustBeReported'] = False
		snmp.RWcommunityACL['mustBeReported'] = False
	else:
		SNMPcommunity = snmp.RWcommunity['cmdInCfg'].split(' ')
		RWsecure = SNMPsecureCommunity(SNMPcommunity[2])
		if RWsecure == False:
			items = searchInXml('snmpRWcommunityHardened')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			snmp.RWcommunity = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3].strip().replace('[%ManagementSubnet]', __builtin__.IPv4trustedNetManagementServers[0][0], 1)),
			"howtofix": (items[3].strip().replace('[%ManagementWildcardMask]', __builtin__.IPv4trustedNetManagementServers[0][3], 1)),
			"cvss": (cvssMetrics)}
		try:
			snmp.RWcommunityACL['cmdInCfg'] = searchRegexString(lines, 'snmp-server community .* (RW|rw) \d')
		except AttributeError:
			pass
		
		if snmp.RWcommunityACL['cmdInCfg'] == None:
			items = searchInXml('snmpRWcommunityHardenedACL')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			snmp.RWcommunityACL = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3].strip().replace('[%ManagementSubnet]', __builtin__.IPv4trustedNetManagementServers[0][0], 1)),
			"howtofix": (items[3].strip().replace('[%ManagementWildcardMask]', __builtin__.IPv4trustedNetManagementServers[0][3], 1)),
			"cvss": (cvssMetrics)}
		else:
			accessListNumber = snmp.RWcommunityACL['cmdInCfg'].split(' ')[4]
			if checkStdACL(lines, accessListNumber) == True:
				snmp.RWcommunityACL['mustBeReported'] = False
			else:
				items = searchInXml('snmpRWcommunityHardenedACL')
				cvssMetrics = str(calculateCVSS2Score(items[5]))
				snmp.RWcommunityACL = {
				"mustBeReported": True,
				"fixImpact": (items[0]),
				"definition": (items[1]),
				"threatInfo": (items[2]),			
				"howtofix": (items[3].strip().replace('[%ManagementSubnet]', __builtin__.IPv4trustedNetManagementServers[0][0], 1)),
				"howtofix": (items[3].strip().replace('[%ManagementWildcardMask]', __builtin__.IPv4trustedNetManagementServers[0][3], 1)),
				"cvss": (cvssMetrics)}

	try:
		snmp.ViewROcommunity['cmdInCfg'] = searchRegexString(lines, 'snmp-server community .* view .* (RO|ro)')
	except AttributeError:
		pass
	if snmp.ViewROcommunity['cmdInCfg'] == None:
		# feature not configured
		snmp.ViewROcommunity['mustBeReported'] = False
		snmp.ViewROcommunityACL['mustBeReported'] = False
	else:
		SNMPcommunity = snmp.ViewROcommunity['cmdInCfg'].split(' ')
		ROsecure = SNMPsecureCommunity(SNMPcommunity[2])
		if ROsecure == False:
			items = searchInXml('ViewsnmpROcommunityHardened')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			snmp.ViewROcommunity = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3].strip().replace('[%ManagementSubnet]', __builtin__.IPv4trustedNetManagementServers[0][0], 1)),
			"howtofix": (items[3].strip().replace('[%ManagementWildcardMask]', __builtin__.IPv4trustedNetManagementServers[0][3], 1)),
			"cvss": (cvssMetrics)}
		try:
			snmp.ViewROcommunityACL['cmdInCfg'] = searchRegexString(lines, 'snmp-server community .* view .* (RO|ro) \d')
		except AttributeError:
			pass
		
		if snmp.ViewROcommunityACL['cmdInCfg'] == None:
			items = searchInXml('ViewsnmpROcommunityHardenedACL')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			snmp.ViewROcommunityACL = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3].strip().replace('[%ManagementSubnet]', __builtin__.IPv4trustedNetManagementServers[0][0], 1)),
			"howtofix": (items[3].strip().replace('[%ManagementWildcardMask]', __builtin__.IPv4trustedNetManagementServers[0][3], 1)),
			"cvss": (cvssMetrics)}
		else:
			accessListNumber = snmp.ViewROcommunityACL['cmdInCfg'].split(' ')[4]
			if checkStdACL(lines, accessListNumber) == True:
				snmp.ViewROcommunityACL['mustBeReported'] = False
			else:
				items = searchInXml('ViewsnmpROcommunityHardenedACL')
				cvssMetrics = str(calculateCVSS2Score(items[5]))
				snmp.ViewROcommunityACL = {
				"mustBeReported": True,
				"fixImpact": (items[0]),
				"definition": (items[1]),
				"threatInfo": (items[2]),			
				"howtofix": (items[3].strip().replace('[%ManagementSubnet]', __builtin__.IPv4trustedNetManagementServers[0][0], 1)),
				"howtofix": (items[3].strip().replace('[%ManagementWildcardMask]', __builtin__.IPv4trustedNetManagementServers[0][3], 1)),
				"cvss": (cvssMetrics)}

	try:
		snmp.ViewRWcommunity['cmdInCfg'] = searchRegexString(lines, 'snmp-server community .* view .* (RW|rw)')
	except AttributeError:
		pass
	if snmp.ViewRWcommunity['cmdInCfg'] == None:
		# feature not configured
		snmp.ViewRWcommunity['mustBeReported'] = False
		snmp.ViewRWcommunityACL['mustBeReported'] = False
	else:
		SNMPcommunity = snmp.ViewRWcommunity['cmdInCfg'].split(' ')
		RWsecure = SNMPsecureCommunity(SNMPcommunity[2])
		if RWsecure == False:
			items = searchInXml('ViewsnmpRWcommunityHardened')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			snmp.ViewRWcommunity = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3].strip().replace('[%ManagementSubnet]', __builtin__.IPv4trustedNetManagementServers[0][0], 1)),
			"howtofix": (items[3].strip().replace('[%ManagementWildcardMask]', __builtin__.IPv4trustedNetManagementServers[0][3], 1)),
			"cvss": (cvssMetrics)}
		try:
			snmp.ViewRWcommunityACL['cmdInCfg'] = searchRegexString(lines, 'snmp-server community .* view .* (RW|rw) \d')
		except AttributeError:
			pass
		
		if snmp.ViewRWcommunityACL['cmdInCfg'] == None:
			items = searchInXml('snmpRWcommunityHardenedACL')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			snmp.ViewRWcommunityACL = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3].strip().replace('[%ManagementSubnet]', __builtin__.IPv4trustedNetManagementServers[0][0], 1)),
			"howtofix": (items[3].strip().replace('[%ManagementWildcardMask]', __builtin__.IPv4trustedNetManagementServers[0][3], 1)),
			"cvss": (cvssMetrics)}
		else:
			accessListNumber = snmp.ViewRWcommunityACL['cmdInCfg'].split(' ')[4]
			if checkStdACL(lines, accessListNumber) == True:
				snmp.ViewRWcommunityACL['mustBeReported'] = False
			else:
				items = searchInXml('ViewsnmpRWcommunityHardenedACL')
				cvssMetrics = str(calculateCVSS2Score(items[5]))
				snmp.ViewRWcommunityACL = {
				"mustBeReported": True,
				"fixImpact": (items[0]),
				"definition": (items[1]),
				"threatInfo": (items[2]),			
				"howtofix": (items[3].strip().replace('[%ManagementSubnet]', __builtin__.IPv4trustedNetManagementServers[0][0], 1)),
				"howtofix": (items[3].strip().replace('[%ManagementWildcardMask]', __builtin__.IPv4trustedNetManagementServers[0][3], 1)),
				"cvss": (cvssMetrics)}

	try:
		snmp.snmpV3['cmdInCfg'] = searchRegexString(lines, 'snmp-server group .* v3 (auth|priv)')
	except AttributeError:
		pass
	if snmp.snmpV3['cmdInCfg'] == None:
		# feature not configured
		items = searchInXml('snmpVersion3')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		snmp.snmpV3 = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3].strip().replace('[%ManagementSubnet]', __builtin__.IPv4trustedNetManagementServers[0][0], 1)),
		"howtofix": (items[3].strip().replace('[%ManagementWildcardMask]', __builtin__.IPv4trustedNetManagementServers[0][3], 1)),
		"cvss": (cvssMetrics)}

	else:
		snmp.snmpV3['mustBeReported'] = False		

	toBeReturned = ''
	if snmp.ROcommunity['mustBeReported'] == True:
		toBeReturned = snmp.ROcommunity['definition'] + '\n' + snmp.ROcommunity['threatInfo'] + '\n\n' + snmp.ROcommunity['howtofix'] + '\n'
	if snmp.ROcommunityACL['mustBeReported'] == True:
		toBeReturned = toBeReturned + snmp.ROcommunityACL['definition'] + '\n' + snmp.ROcommunityACL['threatInfo'] + '\n\n' + snmp.ROcommunityACL['howtofix'] + '\n'
	if snmp.RWcommunity['mustBeReported'] == True:
		toBeReturned = toBeReturned + snmp.RWcommunity['definition'] + '\n' + snmp.RWcommunity['threatInfo'] + '\n\n' + snmp.RWcommunity['howtofix'] + '\n'
	if snmp.RWcommunityACL['mustBeReported'] == True:
		toBeReturned = toBeReturned + snmp.RWcommunityACL['definition'] + '\n' + snmp.RWcommunityACL['threatInfo'] + '\n\n' + snmp.RWcommunityACL['howtofix'] + '\n'
	if snmp.ViewROcommunity['mustBeReported'] == True:
		toBeReturned = toBeReturned + snmp.ViewROcommunity['definition'] + '\n' + snmp.ViewROcommunity['threatInfo'] + '\n\n' + snmp.ViewROcommunity['howtofix'] + '\n'
	if snmp.ViewROcommunityACL['mustBeReported'] == True:
		toBeReturned = toBeReturned + snmp.ViewROcommunityACL['definition'] + '\n' + snmp.ViewROcommunityACL['threatInfo'] + '\n\n' + snmp.ViewROcommunityACL['howtofix'] + '\n'
	if snmp.ViewRWcommunity['mustBeReported'] == True:
		toBeReturned = toBeReturned + snmp.ViewRWcommunity['definition'] + '\n' + snmp.ViewRWcommunity['threatInfo'] + '\n\n' + snmp.ViewRWcommunity['howtofix'] + '\n'
	if snmp.ViewRWcommunityACL['mustBeReported'] == True:
		toBeReturned = toBeReturned + snmp.ViewRWcommunityACL['definition'] + '\n' + snmp.ViewRWcommunityACL['threatInfo'] + '\n\n' + snmp.ViewRWcommunityACL['howtofix'] + '\n'
	if snmp.snmpV3['mustBeReported'] == True:
		toBeReturned = toBeReturned + snmp.snmpV3['definition'] + '\n' + snmp.snmpV3['threatInfo'] + '\n\n' + snmp.snmpV3['howtofix'] + '\n'

	return toBeReturned

def analyzorSyslog(lines, syslog):
	try:
		syslog.Server['cmdInCfg'] = searchString(lines, 'logging host')
	except AttributeError:
		pass
	if syslog.Server['cmdInCfg'] == None:
		# feature not configured
		items = searchInXml('syslogServer')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		
		syslogHost = ''
		for entry in __builtin__.IPv4trustedNetManagementServers:
			if entry[1] == '32':
				syslogHost = entry[0]
		if len(syslogHost) > 0:		
			syslog.Server = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3].strip().replace('[%ManagementSyslog]', syslogHost, 1)),
			"cvss": (cvssMetrics)}
		else:
			syslog.Server = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3].strip().replace('[%ManagementSyslog]', 'syslog-IPv4-address', 1)),
			"cvss": (cvssMetrics)}
		
	else:
		syslog.Server['mustBeReported'] = False

	try:
		syslog.levelTrap['cmdInCfg'] = searchString(lines, 'logging trap')
	except AttributeError:
		pass
	if syslog.levelTrap['cmdInCfg'] == None:
		# feature not configured
		items = searchInXml('syslogLevelTrap')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		syslog.levelTrap = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}
	else:
		level = syslog.levelTrap['cmdInCfg'].split(' ')[2]
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

		if int(level) == 6: 
			syslog.levelTrap['mustBeReported'] = False
		else:
			items = searchInXml('syslogLevelTrap')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			syslog.levelTrap = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}	

	try:
		syslog.levelBuffered['cmdInCfg'] = searchRegexString(lines, 'logging buffered \d')
	except AttributeError:
		pass
	if syslog.levelBuffered['cmdInCfg'] == None:
		# feature not configured
		items = searchInXml('syslogLevelBuffered')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		syslog.levelBuffered = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}
	else:
		level = syslog.levelBuffered['cmdInCfg'].split(' ')[2]
		if int(level) == 6: 
			syslog.levelBuffered['mustBeReported'] = False
		else:
			items = searchInXml('syslogLevelBuffered')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			syslog.levelBuffered = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}			

	try:
		syslog.loggingConsole['cmdInCfg'] = searchString(lines, 'no logging console')
	except AttributeError:
		pass
	if syslog.loggingConsole['cmdInCfg'] == None:
		# feature not configured
		items = searchInXml('syslogConsole')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		syslog.loggingConsole = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}
	else:
		syslog.loggingConsole['mustBeReported'] = False
		
	try:
		syslog.loggingMonitor['cmdInCfg'] = searchString(lines, 'no logging monitor')
	except AttributeError:
		pass
	if syslog.loggingMonitor['cmdInCfg'] == None:
		# feature not configured
		items = searchInXml('syslogMonitor')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		syslog.loggingMonitor = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}
	else:
		syslog.loggingMonitor['mustBeReported'] = False		

	try:
		syslog.loggingBuffered['cmdInCfg'] = searchRegexString(lines, 'logging buffered .* .*')
	except AttributeError:
		pass
	if syslog.loggingBuffered['cmdInCfg'] == None:
		# feature not configured
		items = searchInXml('syslogBuffered')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		syslog.loggingBuffered = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}
	else:
		size = syslog.loggingBuffered['cmdInCfg'].split(' ')[2]
		level = syslog.loggingBuffered['cmdInCfg'].split(' ')[3]
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
			syslog.loggingBuffered['mustBeReported'] = False
		else:
			items = searchInXml('syslogBuffered')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			syslog.loggingBuffered = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
			
	try:
		syslog.Interface['cmdInCfg'] = searchString(lines, 'logging source-interface loopback')
	except AttributeError:
		pass
	if syslog.Interface['cmdInCfg'] == None:
		# feature not configured
		items = searchInXml('syslogInterface')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		syslog.Interface = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}
	else:
		syslog.Interface['mustBeReported'] = False
		
	try:
		syslog.timestamp['cmdInCfg'] = searchString(lines, 'service timestamps log datetime msec show-timezone')
	except AttributeError:
		pass
	if syslog.timestamp['cmdInCfg'] == None:
		# feature not configured
		items = searchInXml('syslogTimestamp')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		syslog.timestamp = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}
	else:
		syslog.timestamp['mustBeReported'] = False			

	if __builtin__.deviceType == 'router':
		try:
			syslog.serverarp['cmdInCfg'] = searchString(lines, 'logging server-arp')
		except AttributeError:
			pass
		if syslog.serverarp['cmdInCfg'] == None:
			# feature not configured
			if __builtin__.iosVersion >= 12.3:
				items = searchInXml('syslogServerArp')
				cvssMetrics = str(calculateCVSS2Score(items[5]))
				syslog.serverarp = {
				"mustBeReported": True,
				"fixImpact": (items[0]),
				"definition": (items[1]),
				"threatInfo": (items[2]),			
				"howtofix": (items[3]),
				"cvss": (cvssMetrics)}
			else:
				# upgrade to >= 12.3 to get the feature
				items = searchInXml('syslogServerArp')
				cvssMetrics = str(calculateCVSS2Score(items[5]))
				syslog.serverarp = {
				"mustBeReported": True,
				"fixImpact": (items[0]),
				"definition": (items[1]),
				"threatInfo": (items[2]),			
				"howtofix": (items[4]),
				"cvss": (cvssMetrics)}		
		else:
			syslog.serverarp['mustBeReported'] = False	

	toBeReturned = ''
	if syslog.Server['mustBeReported'] == True:
		toBeReturned = syslog.Server['definition'] + '\n' + syslog.Server['threatInfo'] + '\n\n' + syslog.Server['howtofix'] + '\n'
	if syslog.levelTrap['mustBeReported'] == True:
		toBeReturned = toBeReturned + syslog.levelTrap['definition'] + '\n' + syslog.levelTrap['threatInfo'] + '\n\n' + syslog.levelTrap['howtofix'] + '\n'
	if syslog.levelBuffered['mustBeReported'] == True:
		toBeReturned = toBeReturned + syslog.levelBuffered['definition'] + '\n' + syslog.levelBuffered['threatInfo'] + '\n\n' + syslog.levelBuffered['howtofix'] + '\n'
	if syslog.loggingConsole['mustBeReported'] == True:
		toBeReturned = toBeReturned + syslog.loggingConsole['definition'] + '\n' + syslog.loggingConsole['threatInfo'] + '\n\n' + syslog.loggingConsole['howtofix'] + '\n'
	if syslog.loggingMonitor['mustBeReported'] == True:
		toBeReturned = toBeReturned + syslog.loggingMonitor['definition'] + '\n' + syslog.loggingMonitor['threatInfo'] + '\n\n' + syslog.loggingMonitor['howtofix'] + '\n'
	if syslog.loggingBuffered['mustBeReported'] == True:
		toBeReturned = toBeReturned + syslog.loggingBuffered['definition'] + '\n' + syslog.loggingBuffered['threatInfo'] + '\n\n' + syslog.loggingBuffered['howtofix'] + '\n'
	if syslog.Interface['mustBeReported'] == True:
		toBeReturned = toBeReturned + syslog.Interface['definition'] + '\n' + syslog.Interface['threatInfo'] + '\n\n' + syslog.Interface['howtofix'] + '\n'
	if syslog.timestamp['mustBeReported'] == True:
		toBeReturned = toBeReturned + syslog.timestamp['definition'] + '\n' + syslog.timestamp['threatInfo'] + '\n\n' + syslog.timestamp['howtofix'] + '\n'
	if syslog.serverarp['mustBeReported'] == True:
		toBeReturned = toBeReturned + syslog.serverarp['definition'] + '\n' + syslog.serverarp['threatInfo'] + '\n\n' + syslog.serverarp['howtofix'] + '\n'

	return toBeReturned


def analyzorArchive(lines, archive):
	try:
		archive.configuration['cmdInCfg'] = searchRegexString(lines, '^archive$')
	except AttributeError:
		pass
	if archive.configuration['cmdInCfg'] != None:
		# feature already configured
		if searchRegexString(lines, 'time-period') != None:
			archive.configuration['mustBeReported'] = False
		else:
			items = searchInXml('archiveConfiguration')
			if __builtin__.iosVersion >= 12.37:
				cvssMetrics = str(calculateCVSS2Score(items[5]))
				archive.configuration = {
				"mustBeReported": True,
				"fixImpact": (items[0]),
				"definition": (items[1]),
				"threatInfo": (items[2]),			
				"howtofix": (items[3]),
				"cvss": (cvssMetrics)}
			else:
			# upgrade to >= 12.37 to get the feature
				cvssMetrics = str(calculateCVSS2Score(items[5]))
				archive.configuration = {
				"mustBeReported": True,
				"fixImpact": (items[0]),
				"definition": (items[1]),
				"threatInfo": (items[2]),			
				"howtofix": (items[4]),
				"cvss": (cvssMetrics)}
	
	try:
		archive.exclusive['cmdInCfg'] = searchString(lines, 'configuration mode exclusive auto')
	except AttributeError:
		pass
	if archive.exclusive['cmdInCfg'] != None:
		# feature already configured
		archive.exclusive['mustBeReported'] = False
	else:
		items = searchInXml('archiveExclusive')
		if __builtin__.iosVersion >= 12.314:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			archive.exclusive = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			# upgrade to >= 12.314 to get the feature
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			archive.exclusive = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[4]),
			"cvss": (cvssMetrics)}

	try:
		archive.secureBoot['cmdInCfg'] = searchString(lines, 'secure boot-image')
	except AttributeError:
		pass
	if archive.secureBoot['cmdInCfg'] != None:
		# feature already configured
		archive.secureBoot['mustBeReported'] = False
	else:
		items = searchInXml('archiveSecureImage')
		if __builtin__.iosVersion >= 12.38:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			archive.secureBoot = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			# upgrade to >= 12.38 to get the feature
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			archive.secureBoot = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[4]),
			"cvss": (cvssMetrics)}			
			
	try:
		archive.secureConfig['cmdInCfg'] = searchString(lines, 'secure boot-config')
	except AttributeError:
		pass
	if archive.secureConfig['cmdInCfg'] != None:
		# feature already configured
		archive.secureConfig['mustBeReported'] = False
	else:
		items = searchInXml('archiveSecureConfig')
		if __builtin__.iosVersion >= 12.38:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			archive.secureConfig = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			# upgrade to >= 12.38 to get the feature
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			archive.secureConfig = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[4]),
			"cvss": (cvssMetrics)}
			
	try:
		archive.logs['cmdInCfg'] = searchRegexString(lines, '^archive$')
	except AttributeError:
		pass
	if archive.logs['cmdInCfg'] != None:
		# feature already configured
		if ( (searchString(lines, 'hidekeys') != None) and (searchString(lines, 'logging enable') != None )):
			archive.logs['mustBeReported'] = False
		else:
			items = searchInXml('archiveLogs')
			if __builtin__.iosVersion >= 12.34:
				cvssMetrics = str(calculateCVSS2Score(items[5]))
				archive.logs = {
				"mustBeReported": True,
				"fixImpact": (items[0]),
				"definition": (items[1]),
				"threatInfo": (items[2]),			
				"howtofix": (items[3]),
				"cvss": (cvssMetrics)}
			else:
				# upgrade to >= 12.34 to get the feature
				cvssMetrics = str(calculateCVSS2Score(items[5]))
				archive.logs = {
				"mustBeReported": True,
				"fixImpact": (items[0]),
				"definition": (items[1]),
				"threatInfo": (items[2]),			
				"howtofix": (items[4]),
				"cvss": (cvssMetrics)}

	toBeReturned = ''
	if archive.configuration['mustBeReported'] == True:
		toBeReturned = archive.configuration['definition'] + '\n' + archive.configuration['threatInfo'] + '\n\n' + archive.configuration['howtofix'] + '\n'
	if archive.exclusive['mustBeReported'] == True:
		toBeReturned = toBeReturned + archive.exclusive['definition'] + '\n' + archive.exclusive['threatInfo'] + '\n\n' + archive.exclusive['howtofix'] + '\n'
	if archive.secureBoot['mustBeReported'] == True:
		toBeReturned = toBeReturned + archive.secureBoot['definition'] + '\n' + archive.secureBoot['threatInfo'] + '\n\n' + archive.secureBoot['howtofix'] + '\n'
	if archive.secureConfig['mustBeReported'] == True:
		toBeReturned = toBeReturned + archive.secureConfig['definition'] + '\n' + archive.secureConfig['threatInfo'] + '\n\n' + archive.secureConfig['howtofix'] + '\n'
	if archive.logs['mustBeReported'] == True:
		toBeReturned = toBeReturned + archive.logs['definition'] + '\n' + archive.logs['threatInfo'] + '\n\n' + archive.logs['howtofix'] + '\n'

	return toBeReturned

def analyzorICMPRedirects(icmpRedirects, fullConfig, ifaceCfg):
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
				icmpRedirects.redirects['mustBeReported'] = True		

	if icmpRedirects.redirects['mustBeReported'] == True:
		items = searchInXml('ipICMPredirects')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		icmpRedirects.redirects['fixImpact'] = items[0]
		icmpRedirects.redirects['definition'] = items[1]
		icmpRedirects.redirects['threatInfo'] = items[2]
		icmpRedirects.redirects['howtofix'] = items[3]
		icmpRedirects.redirects['cvss'] = cvssMetrics

		if icmpRedirects.redirects['enabledIfsFeature']:
			icmpRedirects.redirects['howtofix'] = icmpRedirects.redirects['howtofix'].strip().replace('[%RedirectifsDisabled]', ", ".join(icmpRedirects.redirects['enabledIfsFeature']), 1)
		else:
			icmpRedirects.redirects['howtofix'] = icmpRedirects.redirects['howtofix'].strip().replace('[%RedirectifsDisabled]', "None", 1)
		if icmpRedirects.redirects['disabledIfsFeature']:
			icmpRedirects.redirects['howtofix'] = icmpRedirects.redirects['howtofix'].strip().replace('[%RedirectifsEnabled]', ", ".join(icmpRedirects.redirects['disabledIfsFeature']), 1)
		else:
			icmpRedirects.redirects['howtofix'] = icmpRedirects.redirects['howtofix'].strip().replace('[%RedirectifsEnabled]', "None", 1)

		return icmpRedirects.redirects['definition'] + icmpRedirects.redirects['threatInfo'] + icmpRedirects.redirects['howtofix']

	toBeReturned = ''
	if icmpRedirects.redirects['mustBeReported'] == True:
		toBeReturned = icmpRedirects.redirects['definition'] + '\n' + icmpRedirects.redirects['threatInfo'] + '\n\n' + icmpRedirects.redirects['howtofix'] + '\n'

	return toBeReturned


def analyzorICMPUnreachable(icmpUnreachable, fullConfig, ifaceCfg):
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
				icmpUnreachable.unreachable['mustBeReported'] = True		

	try:
		icmpUnreachable.unreachable['unreachableRate'] = searchString(fullConfig, 'ip icmp rate-limit unreachable')
	except AttributeError:
		pass
	if icmpUnreachable.unreachable['unreachableRate'] == None:
		icmpUnreachable.unreachable['mustBeReported'] = True

	if icmpUnreachable.unreachable['mustBeReported'] == True:
		items = searchInXml('ipICMPunreachable')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
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
	if icmpUnreachable.unreachable['mustBeReported'] == True:
		toBeReturned = icmpUnreachable.unreachable['definition'] + '\n' + icmpUnreachable.unreachable['threatInfo'] + '\n\n' + icmpUnreachable.unreachable['howtofix'] + '\n'

	return toBeReturned

def analyzorARPproxy(proxyArp, fullConfig, ifaceCfg):
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
				proxyArp.proxy['mustBeReported'] = True		

	if proxyArp.proxy['mustBeReported'] == True:
		items = searchInXml('proxyArp')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
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
	if proxyArp.proxy['mustBeReported'] == True:
		toBeReturned = proxyArp.proxy['definition'] + '\n' + proxyArp.proxy['threatInfo'] + '\n\n' + proxyArp.proxy['howtofix'] + '\n'

	return toBeReturned

def analyzorNtp(lines, ntp):
	try:
		ntp.authentication['authenticate'] = searchString(lines, 'ntp authenticate')
	except AttributeError:
		pass
	try:
		ntp.authentication['key'] = searchString(lines, 'ntp authentication-key')
	except AttributeError:
		pass	

	if ( (ntp.authentication['authenticate'] == None) or (ntp.authentication['key'] == None) ):
		ntp.authentication['mustBeReported'] = True
	
	if ntp.authentication['mustBeReported'] == True:
		items = searchInXml('ntpAuthentication')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		ntp.authentication = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	toBeReturned = ''
	if ntp.authentication['mustBeReported'] == True:
		toBeReturned = ntp.authentication['definition'] + '\n' + ntp.authentication['threatInfo'] + '\n\n' + ntp.authentication['howtofix'] + '\n'

	return toBeReturned

def analyzorBgp(lines, bgp):

	remoteAsCount = 0
	ttlSecurityCount = 0
	sessionPasswordCount = 0
	maxPrefixesCount = 0
	prefixListInCount = 0
	prefixListOutCount = 0
	aspathListInCount = 0
	aspathListOutCount = 0
	
	if searchString(lines, 'router bgp') == None:
		return
	remoteAsCount = searchRegexStringCount(lines, 'neighbor .* remote-as .*')
	ttlSecurityCount = searchRegexStringCount(lines, 'neighbor .* ttl-security hops .*')
	sessionPasswordCount = searchRegexStringCount(lines, 'neighbor .* password .*')
	maxPrefixesCount = searchRegexStringCount(lines, 'neighbor .* maximum-prefix .*')
	prefixListInCount = searchRegexStringCount(lines, 'neighbor .* prefix-list .* in')
	prefixListOutCount = searchRegexStringCount(lines, 'neighbor .* prefix-list .* out')
	aspathListInCount = searchRegexStringCount(lines, 'neighbor .* filter-list .* in')
	aspathListOutCount = searchRegexStringCount(lines, 'neighbor .* filter-list .* out')

	if ttlSecurityCount < remoteAsCount:
		bgp.ttlSecurity['mustBeReported'] = True

	if sessionPasswordCount < remoteAsCount:
		bgp.sessionPassword['mustBeReported'] = True

	if maxPrefixesCount < remoteAsCount:
		bgp.maxPrefixes['mustBeReported'] = True

	if prefixListInCount < remoteAsCount:
		bgp.prefixList['mustBeReported'] = True

	if prefixListOutCount < remoteAsCount:
		bgp.prefixList['mustBeReported'] = True

	if aspathListInCount < remoteAsCount:
		bgp.aspathList['mustBeReported'] = True

	if aspathListOutCount < remoteAsCount:
		bgp.aspathList['mustBeReported'] = True

		
	if bgp.ttlSecurity['mustBeReported'] == True:
		items = searchInXml('bgpTTLsecurity')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		bgp.ttlSecurity = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if bgp.sessionPassword['mustBeReported'] == True:
		items = searchInXml('bgpSessionPassword')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		bgp.sessionPassword = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if bgp.maxPrefixes['mustBeReported'] == True:
		items = searchInXml('bgpMaxPrefixes')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		bgp.maxPrefixes = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if bgp.prefixList['mustBeReported'] == True:
		items = searchInXml('bgpPrefixList')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		bgp.prefixList = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if bgp.aspathList['mustBeReported'] == True:
		items = searchInXml('bgpaspathList')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		bgp.aspathList = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	toBeReturned = ''
	if bgp.ttlSecurity['mustBeReported'] == True:
		toBeReturned = bgp.ttlSecurity['definition'] + '\n'+ bgp.ttlSecurity['threatInfo'] + '\n\n' + bgp.ttlSecurity['howtofix'] + '\n'
	if bgp.sessionPassword['mustBeReported'] == True:
		toBeReturned = toBeReturned + bgp.sessionPassword['definition'] + '\n' + bgp.sessionPassword['threatInfo'] + '\n\n' + bgp.sessionPassword['howtofix'] + '\n'
	if bgp.maxPrefixes['mustBeReported'] == True:
		toBeReturned = toBeReturned + bgp.maxPrefixes['definition'] + '\n' + bgp.maxPrefixes['threatInfo'] + '\n\n' + bgp.maxPrefixes['howtofix'] + '\n'
	if bgp.prefixList['mustBeReported'] == True:
		toBeReturned = toBeReturned + bgp.prefixList['definition'] + '\n' + bgp.prefixList['threatInfo'] + '\n\n' + bgp.prefixList['howtofix'] + '\n'
	if bgp.aspathList['mustBeReported'] == True:
		toBeReturned = toBeReturned + bgp.aspathList['definition'] + '\n' + bgp.aspathList['threatInfo'] + '\n\n' + bgp.aspathList['howtofix'] + '\n'

	return toBeReturned
		
def analyzorEigrp(lines, eigrp, ifaceCfg):
	if searchString(lines, 'router eigrp') == None:
		return
	authModeMD5 = None
	eigrpInstances = 0
	eigrpInstances = searchStringCount(lines, 'router eigrp')
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
						eigrp.passiveDefault['cmdInCfg'] = searchString(eigrpLines, 'passive-interface default')
					except AttributeError:
						pass
					try:
						eigrp.routeFilteringIn['cmdInCfg'] = searchRegexString(eigrpLines, 'distribute-list prefix .* in .*')
					except AttributeError:
						pass
					try:
						eigrp.routeFilteringOut['cmdInCfg'] = searchRegexString(eigrpLines, 'distribute-list prefix .* out .*')
					except AttributeError:
						pass
					
				for line in eigrpLines:
					if line.find('no passive-interface') != -1:
						eigrp.activeIfaces.append(line.split(' ')[2])
													
				if ( (eigrp.passiveDefault['cmdInCfg'] == None) ):
						eigrp.passiveDefault['asn'].append(v.split(' ')[2].strip())
						eigrp.passiveDefault['mustBeReported'] = True
						
				if ( (eigrp.routeFilteringIn['cmdInCfg'] == None) ):
					eigrp.routeFilteringIn['asn'].append(v.split(' ')[2].strip())
					eigrp.routeFilteringIn['mustBeReported'] = True
					
				if ( (eigrp.routeFilteringOut['cmdInCfg'] == None) ):
					eigrp.routeFilteringOut['asn'].append(v.split(' ')[2].strip())
					eigrp.routeFilteringOut['mustBeReported'] = True					

				for ifaceName in eigrp.activeIfaces:
					for index in range(0, len(ifaceCfg)):
						if ifaceCfg[index].name.strip() == ifaceName.strip():
							authModeMD5 = searchRegexString(ifaceCfg[index].configuration, 'ip authentication mode eigrp .* md5')
							if authModeMD5 == None:
								eigrp.authModeMD5['interfaces'].append(ifaceName.strip())
								eigrp.authModeMD5['asn'].append(v.split(' ')[2].strip())
								eigrp.authModeMD5['mustBeReported'] = True
					
				if eigrp.passiveDefault['mustBeReported'] == True:
					items = searchInXml('eigrpPassiveDefault')
					cvssMetrics = str(calculateCVSS2Score(items[5]))
					eigrp.passiveDefault = {
					"mustBeReported": True,
					"asn": eigrp.passiveDefault['asn'],
					"fixImpact": (items[0]),
					"definition": (items[1]),
					"threatInfo": (items[2]),			
					"howtofix": (items[3]),
					"cvss": (cvssMetrics)}

				if eigrp.authModeMD5['mustBeReported'] == True:
					items = searchInXml('eigrpAuthModeMD5')
					cvssMetrics = str(calculateCVSS2Score(items[5]))
					eigrp.authModeMD5 = {
					"mustBeReported": True,
					"interfaces": eigrp.authModeMD5['interfaces'],
					"asn": eigrp.authModeMD5['asn'],
					"fixImpact": (items[0]),
					"definition": (items[1]),
					"threatInfo": (items[2]),			
					"howtofix": (items[3]),
					"cvss": (cvssMetrics)}

				if eigrp.routeFilteringIn['mustBeReported'] == True:
					items = searchInXml('eigrpRouteFilteringIn')
					cvssMetrics = str(calculateCVSS2Score(items[5]))
					eigrp.routeFilteringIn = {
					"mustBeReported": True,
					"asn": eigrp.routeFilteringIn['asn'],
					"fixImpact": (items[0]),
					"definition": (items[1]),
					"threatInfo": (items[2]),			
					"howtofix": (items[3]),
					"cvss": (cvssMetrics)}						

				if eigrp.routeFilteringOut['mustBeReported'] == True:
					items = searchInXml('eigrpRouteFilteringOut')
					cvssMetrics = str(calculateCVSS2Score(items[5]))
					eigrp.routeFilteringOut = {
					"mustBeReported": True,
					"asn": eigrp.routeFilteringOut['asn'],
					"fixImpact": (items[0]),
					"definition": (items[1]),
					"threatInfo": (items[2]),			
					"howtofix": (items[3]),
					"cvss": (cvssMetrics)}

	toBeReturned = ''
	if eigrp.passiveDefault['mustBeReported'] == True:
		toBeReturned = eigrp.passiveDefault['definition'] + '\n' + eigrp.passiveDefault['threatInfo'] + '\n\n' + eigrp.passiveDefault['howtofix'] + '\n'
	if eigrp.authModeMD5['mustBeReported'] == True:
		toBeReturned = toBeReturned + eigrp.authModeMD5['definition'] + '\n' + eigrp.authModeMD5['threatInfo'] + '\n\n' + eigrp.authModeMD5['howtofix'] + '\n'
	if eigrp.routeFilteringIn['mustBeReported'] == True:
		toBeReturned = toBeReturned + eigrp.routeFilteringIn['definition'] + '\n' + eigrp.routeFilteringIn['threatInfo'] + '\n\n' + eigrp.routeFilteringIn['howtofix'] + '\n'
	if eigrp.routeFilteringOut['mustBeReported'] == True:
		toBeReturned = toBeReturned + eigrp.routeFilteringOut['definition'] + '\n' + eigrp.routeFilteringOut['threatInfo'] + '\n\n' + eigrp.routeFilteringOut['howtofix'] + '\n'

	return toBeReturned

def analyzorRip(lines, rip, ifaceCfg):
	if searchString(lines, 'router rip') == None:
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
	ripMask = searchRegexString(ripLines, 'network .* .*')
	if ripMask != None:
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
						ifIPmask = searchRegexString(ifaceCfg[index].configuration, 'ip address .* .*')
						if ifIPmask != None:
							ipTuple = ifIPmask.split(' ')
							ipAddress = ipTuple[2]
							Mask = ipTuple[3]
							if ripNet == networkAddress(ipAddress, Mask):
								ripMD5 = searchString(ifaceCfg[index].configuration, 'ip rip authentication mode md5')
								if ripMD5 == None:
									MD5notFound = True
									rip.authModeMD5['interfaces'].append(ifaceCfg[index].name.strip())
									rip.authModeMD5['mustBeReported'] = True

	if rip.authModeMD5['mustBeReported'] == True:
		items = searchInXml('ripAuthModeMD5')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		rip.authModeMD5 = {
		"mustBeReported": True,
		"interfaces": rip.authModeMD5['interfaces'],
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	toBeReturned = ''
	if rip.authModeMD5['mustBeReported'] == True:
		toBeReturned = rip.authModeMD5['definition'] + '\n' + rip.authModeMD5['threatInfo'] + '\n\n' + rip.authModeMD5['howtofix'] + '\n'

	return toBeReturned


def analyzorOspf(lines, ospf, ifaceCfg):
	if searchString(lines, 'router ospf') == None:
		return
	authModeMD5 = None
	ospfInstances = 0
	ospfInstances = searchStringCount(lines, 'router ospf')
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
						ospf.passiveDefault['cmdInCfg'] = searchString(ospfLines, 'passive-interface default')
					except AttributeError:
						pass
					try:
						ospf.maxLSA['cmdInCfg'] = searchRegexString(ospfLines, 'max-lsa .*')
					except AttributeError:
						pass
									
				if ( (ospf.passiveDefault['cmdInCfg'] == None) ):
					ospf.passiveDefault['pid'].append(currentPid)
					ospf.passiveDefault['mustBeReported'] = True

				if ( (ospf.routeFilteringIn['cmdInCfg'] == None) ):
					ospf.routeFilteringIn['pid'].append(currentPid)
					ospf.routeFilteringIn['mustBeReported'] = True

				if ( (ospf.routeFilteringOut['cmdInCfg'] == None) ):
					ospf.routeFilteringOut['pid'].append(currentPid)
					ospf.routeFilteringOut['mustBeReported'] = True

				if ( (ospf.maxLSA['cmdInCfg'] == None) ):
					ospf.maxLSA['pid'].append(currentPid)
					ospf.maxLSA['mustBeReported'] = True

				ospf.area = []	
				for line in ospfLines:
					if line.find('network',0,8) != -1:
						if not line.split(' ')[4] in ospf.area:
							ospf.area.append(line.split(' ')[4])
				
				for areaNumber in ospf.area:
					areaDigest = False
					searchArea = None
					searchArea = searchRegexString(ospfLines,'area .* authentication message-digest')
					if searchArea != None:
						matchArea = searchArea.split(' ')[1]
						if matchArea == areaNumber:
							areaDigest = True
					
					if areaDigest == False:
						if not areaNumber in ospf.authModeMD5['area']:
							ospf.authModeMD5['area'].append(areaNumber)
						if not currentPid in ospf.authModeMD5['pid']:
							ospf.authModeMD5['pid'].append(currentPid)
						ospf.authModeMD5['mustBeReported'] = True
				
				if ospf.authModeMD5['mustBeReported'] == True:
					for line in ospfLines:
						if line.find('network',0, 8) != -1:
							ospfNet =line.split(' ')[1]
							ifIPmask = None
							for index in range(0, len(ifaceCfg)):
								ifIPmask = searchRegexString(ifaceCfg[index].configuration, 'ip address .* .*')
								if ifIPmask != None:
									ipTuple = ifIPmask.split(' ')
									ipAddress = ipTuple[2]
									Mask = ipTuple[3]
									if ospfNet == networkAddress(ipAddress, Mask):
										ospfMD5 = searchRegexString(ifaceCfg[index].configuration, 'ip ospf message-digest-key .* md5 .*')
										if ospfMD5 == None:
											ospf.authModeMD5['interfaces'].append(ifaceCfg[index].name.strip())

					searchFilterAreaIn = 'area ' + str(areaNumber) + ' filter-list prefix .* in'
					if searchRegexString(ospfLines, searchFilterAreaIn) == None:
						if not areaNumber in ospf.routeFilteringIn['area']:
							ospf.routeFilteringIn['area'].append(areaNumber)

					searchFilterAreaOut = 'area ' + str(areaNumber) + ' filter-list prefix .* out'
					if searchRegexString(ospfLines, searchFilterAreaOut) == None:
						if not areaNumber in ospf.routeFilteringOut['area']:
							ospf.routeFilteringOut['area'].append(areaNumber)
						
						
	if ospf.passiveDefault['mustBeReported'] == True:
		items = searchInXml('ospfPassiveDefault')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		ospf.passiveDefault = {
		"pid": ospf.passiveDefault['pid'],
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if ospf.authModeMD5['mustBeReported'] == True:
		items = searchInXml('ospfAuthModeMD5')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		ospf.authModeMD5 = {
		"mustBeReported": True,
		"pid": ospf.authModeMD5['pid'],
		"area": ospf.authModeMD5['area'],
		"interfaces": ospf.authModeMD5['interfaces'],
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}		
						
	if ospf.routeFilteringIn['mustBeReported'] == True:
		items = searchInXml('ospfRouteFilteringIn')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		ospf.routeFilteringIn = {
		"area": ospf.routeFilteringIn['area'],
		"pid": ospf.routeFilteringIn['pid'],
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}						

	if ospf.routeFilteringOut['mustBeReported'] == True:
		items = searchInXml('ospfRouteFilteringOut')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		ospf.routeFilteringOut = {
		"area": ospf.routeFilteringOut['area'],
		"pid": ospf.routeFilteringOut['pid'],
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if ospf.maxLSA['mustBeReported'] == True:
		items = searchInXml('ospfMaxLSA')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		ospf.maxLSA = {
		"pid": ospf.maxLSA['pid'],
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	toBeReturned = ''
	if ospf.passiveDefault['mustBeReported'] == True:
		toBeReturned = ospf.passiveDefault['definition'] + '\n' + ospf.passiveDefault['threatInfo'] + '\n\n' + ospf.passiveDefault['howtofix'] + '\n'
	if ospf.authModeMD5['mustBeReported'] == True:
		toBeReturned = toBeReturned + ospf.authModeMD5['definition'] + '\n' + ospf.authModeMD5['threatInfo'] + '\n\n' + ospf.authModeMD5['howtofix'] + '\n'
	if ospf.routeFilteringIn['mustBeReported'] == True:
		toBeReturned = toBeReturned + ospf.routeFilteringIn['definition'] + '\n' + ospf.routeFilteringIn['threatInfo'] + '\n\n' + ospf.routeFilteringIn['howtofix'] + '\n'
	if ospf.routeFilteringOut['mustBeReported'] == True:
		toBeReturned = toBeReturned + ospf.routeFilteringOut['definition'] + '\n' + ospf.routeFilteringOut['threatInfo'] + '\n\n' + ospf.routeFilteringOut['howtofix'] + '\n'
	if ospf.maxLSA['mustBeReported'] == True:
		toBeReturned = toBeReturned + ospf.maxLSA['definition'] + '\n' + ospf.maxLSA['threatInfo'] + '\n\n' + ospf.maxLSA['howtofix'] + '\n'

	return toBeReturned

def analyzorGlbp(lines, glbp, ifaceCfg):
	glbpConfigured = []
	for index in ifaceCfg:
		glbpConfigured = searchRegexMultiString(index.configuration,'glbp .* ip .*')
		if len(glbpConfigured) >= 1:
			for indexInstance in glbpConfigured:
				glbpInstance = indexInstance.split(' ')[1]
				authentication = 'glbp ' + glbpInstance + ' authentication md5 key-string .*'
				if searchRegexString(index.configuration,authentication) == None:
					glbp.authModeMD5['mustBeReported'] = True
				
	if glbp.authModeMD5['mustBeReported'] == True:
		items = searchInXml('glbpMD5')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		glbp.authModeMD5 = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	toBeReturned = ''
	if glbp.authModeMD5['mustBeReported'] == True:
		toBeReturned = glbp.authModeMD5['definition'] + '\n' + glbp.authModeMD5['threatInfo'] + '\n\n' + glbp.authModeMD5['howtofix'] + '\n'

	return toBeReturned

	
def analyzorHsrp(lines, hsrp, ifaceCfg):
	hsrpConfigured = []
	for index in ifaceCfg:
		hsrpConfigured = searchRegexMultiString(index.configuration,'hsrp .* ip .*')
		if len(hsrpConfigured) >= 1:
			for indexInstance in hsrpConfigured:
				hsrpInstance = indexInstance.split(' ')[1]
				authentication = 'hsrp ' + hsrpInstance + ' authentication md5 key-string .*'
				if searchRegexString(index.configuration,authentication) == None:
					hsrp.authModeMD5['mustBeReported'] = True
				
	if hsrp.authModeMD5['mustBeReported'] == True:
		items = searchInXml('hsrpMD5')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		hsrp.authModeMD5 = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	toBeReturned = ''
	if hsrp.authModeMD5['mustBeReported'] == True:
		toBeReturned = hsrp.authModeMD5['definition'] + '\n' + hsrp.authModeMD5['threatInfo'] + '\n\n' + hsrp.authModeMD5['howtofix'] + '\n'

	return toBeReturned

def analyzorVrrp(lines, vrrp, ifaceCfg):
	vrrpConfigured = []
	for index in ifaceCfg:
		vrrpConfigured = searchRegexMultiString(index.configuration,'vrrp .* ip .*')
		if len(vrrpConfigured) >= 1:
			for indexInstance in vrrpConfigured:
				vrrpInstance = indexInstance.split(' ')[1]
				authentication = 'vrrp ' + vrrpInstance + ' authentication md5 key-string .*'
				if searchRegexString(index.configuration,authentication) == None:
					vrrp.authModeMD5['mustBeReported'] = True
				
	if vrrp.authModeMD5['mustBeReported'] == True:
		items = searchInXml('vrrpMD5')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		vrrp.authModeMD5 = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	toBeReturned = ''
	if vrrp.authModeMD5['mustBeReported'] == True:
		toBeReturned = vrrp.authModeMD5['definition'] + '\n' + vrrp.authModeMD5['threatInfo'] + '\n\n' + vrrp.authModeMD5['howtofix'] + '\n'

	return toBeReturned

def analyzorIPoptions(lines, ipoptions):

	try:
		ipoptions.drop['cmdInCfg'] = searchString(lines, 'ip options drop')
	except AttributeError:
		pass
	if ipoptions.drop['cmdInCfg'] == None:
		ipoptions.drop['mustBeReported'] = True

	if ipoptions.drop['mustBeReported'] == True:
		items = searchInXml('IPoptions')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		ipoptions.drop = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}		

	toBeReturned = ''
	if ipoptions.drop['mustBeReported'] == True:
		toBeReturned = ipoptions.drop['definition'] + '\n' + ipoptions.drop['threatInfo'] + '\n\n' + ipoptions.drop['howtofix'] + '\n'

	return toBeReturned

def analyzorIPsrcRoute(lines, ipsrcroute):
	
	try:
		ipsrcroute.drop['cmdInCfg'] = searchString(lines, 'no ip source-route')
	except AttributeError:
		pass
	if ipsrcroute.drop['cmdInCfg'] == None:
		ipsrcroute.drop['mustBeReported'] = True

	if ipsrcroute.drop['mustBeReported'] == True:
		items = searchInXml('IPsourceroute')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		ipsrcroute.drop = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	toBeReturned = ''
	if ipsrcroute.drop['mustBeReported'] == True:
		toBeReturned = ipsrcroute.drop['definition'] + '\n' + ipsrcroute.drop['threatInfo'] + '\n\n' + ipsrcroute.drop['howtofix'] + '\n'

	return toBeReturned

def analyzorICMPdeny(lines, denyicmp):

	try:
		denyicmp.filtered['cmdInCfg'] = searchString(lines, 'deny icmp any any')
	except AttributeError:
		pass
	if denyicmp.filtered['cmdInCfg'] == None:
		denyicmp.filtered['mustBeReported'] = True

	if denyicmp.filtered['mustBeReported'] == True:
		items = searchInXml('ICMPdeny')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		denyicmp.filtered = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	toBeReturned = ''
	if denyicmp.filtered['mustBeReported'] == True:
		toBeReturned = denyicmp.filtered['definition'] + '\n' + denyicmp.filtered['threatInfo'] + '\n\n' + denyicmp.filtered['howtofix'] + '\n'

	return toBeReturned
		
def analyzorIPfragments(lines, ipfrags):

	try:
		ipfrags.filtered['tcp'] = searchString(lines, 'deny tcp any any fragments')
	except AttributeError:
		pass
	try:
		ipfrags.filtered['udp'] = searchString(lines, 'deny udp any any fragments')
	except AttributeError:
		pass
	try:
		ipfrags.filtered['icmp'] = searchString(lines, 'deny icmp any any fragments')
	except AttributeError:
		pass
	try:
		ipfrags.filtered['ip'] = searchString(lines, 'deny ip any any fragments')
	except AttributeError:
		pass
	
	if ipfrags.filtered['tcp'] == None:
		ipfrags.filtered['mustBeReported'] = True
	if ipfrags.filtered['udp'] == None:
		ipfrags.filtered['mustBeReported'] = True
	if ipfrags.filtered['icmp'] == None:
		ipfrags.filtered['mustBeReported'] = True
	if ipfrags.filtered['ip'] == None:
		ipfrags.filtered['mustBeReported'] = True

	if ipfrags.filtered['mustBeReported'] == True:
		items = searchInXml('IPfrags')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		ipfrags.filtered = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	toBeReturned = ''
	if ipfrags.filtered['mustBeReported'] == True:
		toBeReturned = ipfrags.filtered['definition'] + '\n' + ipfrags.filtered['threatInfo'] + '\n\n' + ipfrags.filtered['howtofix'] + '\n'

	return toBeReturned

def analyzorURPF(lines, urpf, ifaceCfg):
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
			urpf.spoofing['mustBeReported'] = True		

	if urpf.spoofing['mustBeReported'] == True:
		items = searchInXml('urpf')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		urpf.spoofing['mustBeReported'] = True
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

def analyzorURPFv6(lines, urpfv6, ifaceCfg):

	for j in range(0, len(ifaceCfg)):
		ipv6enable = False
		if searchRegexString(ifaceCfg[j].configuration, '^ipv6 enable$') != None:
			ipv6enable = True
		if ipv6enable == True:
			urpfreachable = False
			if searchRegexString(ifaceCfg[j].configuration, '^ipv6 verify unicast source reachable-via (rx|any)$') == None:
				urpfreachable = True
		 	if searchRegexString(ifaceCfg[j].configuration, '^ipv6 verify unicast reverse-path$') == None and urpfreachable == True:
			 	urpfv6.spoofing['candidates'].append(ifaceCfg[j].name.strip())
			 	urpfv6.spoofing['mustBeReported'] = True

	if urpfv6.spoofing['mustBeReported'] == True:
		items = searchInXml('urpfv6')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		urpfv6.spoofing['mustBeReported'] = True
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

def analyzorPortSecurity(lines, portsecurity, ifaceCfg):
	for i in range(0, len(ifaceCfg)):
		if searchRegexString(ifaceCfg[i].configuration, '^switchport access vlan .*$') != None:
			if searchRegexString(ifaceCfg[i].configuration,'switchport port-security maximum .* vlan access') == None:
				portsecurity.maximumAccess['candidates'].append(ifaceCfg[i].name.strip())
				portsecurity.maximumAccess['mustBeReported'] = True
		if searchRegexString(ifaceCfg[i].configuration, '^switchport voice vlan .*$') != None:
			if searchRegexString(ifaceCfg[i].configuration,'switchport port-security maximum .* vlan voice') == None:
				portsecurity.maximumVoice['candidates'].append(ifaceCfg[i].name.strip())
				portsecurity.maximumVoice['mustBeReported'] = True				
		for line in ifaceCfg[i].configuration:
			if line.find('switchport mode access') != -1:
				break
			if line.find('switchport port-security violation') == -1:
				if not ifaceCfg[i].name.strip() in portsecurity.violation['candidates']:
					if not 'Vlan' or not 'Loopback' in ifaceCfg[i].name.strip():
						portsecurity.violation['candidates'].append(ifaceCfg[i].name.strip())
						portsecurity.violation['mustBeReported'] = True
			if line.find('switchport port-security mac-address sticky') == -1:
				if not ifaceCfg[i].name.strip() in portsecurity.sticky['candidates']:
					if not 'Vlan' or not 'Loopback' in ifaceCfg[i].name.strip():
						portsecurity.sticky['candidates'].append(ifaceCfg[i].name.strip())
						portsecurity.sticky['mustBeReported'] = True
			if re.search('^switchport port-security maximum .*$', line) == None:
				if not ifaceCfg[i].name.strip() in portsecurity.maximumTotal['candidates']:
					if not 'Vlan' or not 'Loopback' in ifaceCfg[i].name.strip():
						portsecurity.maximumTotal['candidates'].append(ifaceCfg[i].name.strip())
						portsecurity.maximumTotal['mustBeReported'] = True


	if portsecurity.violation['mustBeReported'] == True:
		items = searchInXml('portsecurityViolation')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		portsecurity.violation = {
		"candidates": portsecurity.violation['candidates'],
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if portsecurity.sticky['mustBeReported'] == True:
		items = searchInXml('portsecuritySticky')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		portsecurity.sticky = {
		"candidates": portsecurity.sticky['candidates'],
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if portsecurity.maximumTotal['mustBeReported'] == True:
		items = searchInXml('portsecurityMaximumTotal')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		portsecurity.maximumTotal = {
		"candidates": portsecurity.maximumTotal['candidates'],
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if portsecurity.maximumAccess['mustBeReported'] == True:
		items = searchInXml('portsecurityMaximumAccess')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		portsecurity.maximumAccess = {
		"candidates": portsecurity.maximumAccess['candidates'],
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}
		
	if portsecurity.maximumVoice['mustBeReported'] == True:
		items = searchInXml('portsecurityMaximumVoice')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		portsecurity.maximumVoice = {
		"candidates": portsecurity.maximumVoice['candidates'],
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	toBeReturned = ''
	if portsecurity.sticky['mustBeReported'] == True:
		toBeReturned = portsecurity.sticky['definition'] + '\n' + portsecurity.sticky['threatInfo'] + '\n\n' + portsecurity.sticky['howtofix'] + '\n'
	if portsecurity.violation['mustBeReported'] == True:
		toBeReturned = toBeReturned + portsecurity.violation['definition'] + '\n' + portsecurity.violation['threatInfo'] + '\n\n' + portsecurity.violation['howtofix'] + '\n'
	if portsecurity.maximumTotal['mustBeReported'] == True:
		toBeReturned = toBeReturned + portsecurity.maximumTotal['definition'] + '\n' + portsecurity.maximumTotal['threatInfo'] + '\n\n' + portsecurity.maximumTotal['howtofix'] + '\n'
	if portsecurity.maximumAccess['mustBeReported'] == True:
		toBeReturned = toBeReturned + portsecurity.maximumAccess['definition'] + '\n' + portsecurity.maximumAccess['threatInfo'] + '\n\n' + portsecurity.maximumAccess['howtofix'] + '\n'
	if portsecurity.maximumVoice['mustBeReported'] == True:
		toBeReturned = toBeReturned + portsecurity.maximumVoice['definition'] + '\n' + portsecurity.maximumVoice['threatInfo'] + '\n\n' + portsecurity.maximumVoice['howtofix'] + '\n'

	return toBeReturned

def analyzorIPv6(lines, ipv6, aclIPv6, ifaceCfg):
	denyRH0 = (None)
	ACLv6name = (None)
	for i in range(0, len(aclIPv6)):
		denyRH0 = searchRegexString(aclIPv6[i].configuration, '^deny ipv6 .* routing-type 0$')
		if denyRH0 != None:
			ACLv6name = aclIPv6[i].name
			for j in range(0, len(ifaceCfg)):
				ipv6enable = False
				if searchRegexString(ifaceCfg[j].configuration, '^ipv6 enable$') != None:
					ipv6enable = True
				if searchRegexString(ifaceCfg[j].configuration, '^ipv6 traffic-filter '+ ACLv6name.strip() +' in$') == None and ipv6enable == True:
					ipv6.rh0['Notfiltered'].append(ifaceCfg[j].name.strip())

		
	try:
		ipv6.rh0['cmdInCfg'] = searchString(lines, 'no ipv6 source-route')
	except AttributeError:
		pass

	if ipv6.rh0['cmdInCfg'] == None:
		if len(ipv6.rh0['Notfiltered']) >= 1:
			ipv6.rh0['mustBeReported'] = True

	if ipv6.rh0['mustBeReported'] == True:
		items = searchInXml('IPv6rh0')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		ipv6.rh0 = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	toBeReturned = ''
	if ipv6.rh0['mustBeReported'] == True:
		toBeReturned = ipv6.rh0['definition'] + '\n' + ipv6.rh0['threatInfo'] + '\n\n' + ipv6.rh0['howtofix'] + '\n'

	return toBeReturned

def analyzorIPSEC(lines, ipsec):
	
	try:
		ipsec.cacIKE['cmdInCfg'] = searchRegexString(lines, '^crypto call admission limit ike sa .*$')
	except AttributeError:
		pass
	try:
		ipsec.cacRSC['cmdInCfg'] = searchRegexString(lines, '^call admission limit .*$')
	except AttributeError:
		pass
	
	if ipsec.cacIKE['cmdInCfg'] == None:
			ipsec.cacIKE['mustBeReported'] = True

	if ipsec.cacRSC['cmdInCfg'] == None:
		ipsec.cacRSC['mustBeReported'] = True

	if ipsec.cacIKE['mustBeReported'] == True:
		items = searchInXml('IPSECcacIKE')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		ipsec.cacIKE = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if ipsec.cacRSC['mustBeReported'] == True:
		items = searchInXml('IPSECcacRSC')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		ipsec.cacRSC = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	toBeReturned = ''
	if ipsec.cacIKE['mustBeReported'] == True:
		toBeReturned = ipsec.cacIKE['definition'] + '\n' + ipsec.cacIKE['threatInfo'] + '\n\n' + ipsec.cacIKE['howtofix'] + '\n'
	if ipsec.cacRSC['mustBeReported'] == True:
		toBeReturned = toBeReturned + ipsec.cacRSC['definition'] + '\n' + ipsec.cacRSC['threatInfo'] + '\n\n' + ipsec.cacRSC['howtofix'] + '\n'

	return toBeReturned

def analyzorTclSH(lines, tclsh):
	
	try:
		tclsh.shell['cmdInCfg'] = searchRegexString(lines, '^event cli pattern \"tclsh\" .*$')
	except AttributeError:
		pass
	if tclsh.shell['cmdInCfg'] == None:
		tclsh.shell['mustBeReported'] = True
		
	if tclsh.shell['mustBeReported'] == True:
		items = searchInXml('tclsh')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		tclsh.shell = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	toBeReturned = ''
	if tclsh.shell['mustBeReported'] == True:
		toBeReturned = tclsh.shell['definition'] + '\n' + tclsh.shell['threatInfo'] + '\n\n' + tclsh.shell['howtofix'] + '\n'

	return toBeReturned


def analyzorTcp(lines, tcp):
	
	try:
		tcp.synwait['cmdInCfg'] = searchRegexString(lines, '^ip tcp synwait-time .*$')
	except AttributeError:
		pass
	if tcp.synwait['cmdInCfg'] == None:
		tcp.synwait['mustBeReported'] = True
	else:
		timer = tcp.synwait.split(' ')[3]
		if int(timer) <= 15:
			tcp.synwait['mustBeReported'] = False	
		else:
			tcp.synwait['mustBeReported'] = True

	if tcp.synwait['mustBeReported'] == True:
		items = searchInXml('tcpsynwait')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		tcp.synwait = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	toBeReturned = ''
	if tcp.synwait['mustBeReported'] == True:
		toBeReturned = tcp.synwait['definition'] + '\n' + tcp.synwait['threatInfo'] + '\n\n' + tcp.synwait['howtofix'] + '\n'

	return toBeReturned

def analyzorLevel2Protocols(lines, level2protocols, ifaceCfg):

	if searchRegexString(lines,'^vtp domain .*$') != None:
		if searchRegexString(lines,'^vtp password .*$') == None:
			level2protocols.vtpsecure['mustBeReported'] = True

	if __builtin__.deviceType != 'router' and searchRegexString(lines,'^spanning-tree portfast bpduguard default$') == None:
			level2protocols.bpduguard['mustBeReported'] = True

	if __builtin__.deviceType == 'switch' and searchRegexString(lines,'^dot1x system-auth-control$') == None:
		level2protocols.dot1x['mustBeReported'] = True
		
	for i in range(0, len(ifaceCfg)):
		if searchRegexString(ifaceCfg[i].configuration, '^switchport mode (access|trunk)$') != None:
			if searchRegexString(ifaceCfg[i].configuration,'^switchport nonegotiate$') == None:
				level2protocols.nonegotiate['candidates'].append(ifaceCfg[i].name.strip())
				level2protocols.nonegotiate['mustBeReported'] = True
			elif searchRegexString(ifaceCfg[i].configuration,'^switchport access vlan 1$') != None:
				level2protocols.vlan1['candidates'].append(ifaceCfg[i].name.strip())
				level2protocols.vlan1['mustBeReported'] = True				

		if searchRegexString(ifaceCfg[i].configuration, '^flowcontrol receive off$') == None:
			if not 'Loopback' in ifaceCfg[i].name.strip() and not 'Vlan' in ifaceCfg[i].name.strip():
				level2protocols.flowcontrol['candidates'].append(ifaceCfg[i].name.strip())
				level2protocols.flowcontrol['mustBeReported'] = True

		if searchRegexString(ifaceCfg[i].configuration, '^shutdown$') != None:	
			if searchRegexString(ifaceCfg[i].configuration,'^switchport access vlan 999$') == None:
				if __builtin__.deviceType == 'switch':
					level2protocols.unusedports['candidates'].append(ifaceCfg[i].name.strip())
					level2protocols.unusedports['mustBeReported'] = True						

	try:
		level2protocols.udld['cmdInCfg'] = searchString(lines, 'no udld enable')
	except AttributeError:
		pass
	
	if level2protocols.udld['cmdInCfg'] == None:
		level2protocols.udld['mustBeReported'] = True

	if level2protocols.nonegotiate['mustBeReported'] == True:
		items = searchInXml('nonegotiate')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		level2protocols.nonegotiate = {
		"candidates": level2protocols.nonegotiate['candidates'],
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if level2protocols.flowcontrol['mustBeReported'] == True:
		items = searchInXml('flowcontrol')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		level2protocols.flowcontrol = {
		"candidates": level2protocols.flowcontrol['candidates'],
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if level2protocols.udld['mustBeReported'] == True:
		items = searchInXml('udld')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		level2protocols.udld = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if level2protocols.vlan1['mustBeReported'] == True:
		items = searchInXml('vlan1')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		level2protocols.vlan1 = {
		"candidates": level2protocols.vlan1['candidates'],
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if (level2protocols.unusedports['mustBeReported'] == True):
		items = searchInXml('unusedports')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		level2protocols.unusedports = {
		"candidates": level2protocols.unusedports['candidates'],
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if level2protocols.vtpsecure['mustBeReported'] == True:
		items = searchInXml('vtpsecure')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		level2protocols.vtpsecure = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if level2protocols.bpduguard['mustBeReported'] == True:
		items = searchInXml('bpduguard')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		level2protocols.bpduguard = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if level2protocols.stproot['mustBeReported'] == True:
		items = searchInXml('stproot')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		level2protocols.stproot = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	if level2protocols.dot1x['mustBeReported'] == True:
		items = searchInXml('dot1x')
		cvssMetrics = str(calculateCVSS2Score(items[5]))
		level2protocols.dot1x = {
		"mustBeReported": True,
		"fixImpact": (items[0]),
		"definition": (items[1]),
		"threatInfo": (items[2]),			
		"howtofix": (items[3]),
		"cvss": (cvssMetrics)}

	toBeReturned = ''
	if level2protocols.nonegotiate['mustBeReported'] == True:
		toBeReturned = level2protocols.nonegotiate['definition'] + '\n' + level2protocols.nonegotiate['threatInfo'] + '\n\n' + level2protocols.nonegotiate['howtofix'] + '\n'
	if level2protocols.flowcontrol['mustBeReported'] == True:
		toBeReturned = toBeReturned + level2protocols.flowcontrol['definition'] + '\n' + level2protocols.flowcontrol['threatInfo'] + '\n\n' + level2protocols.flowcontrol['howtofix'] + '\n'
	if level2protocols.udld['mustBeReported'] == True:
		toBeReturned = toBeReturned + level2protocols.udld['definition'] + '\n' + level2protocols.udld['threatInfo'] + '\n\n' + level2protocols.udld['howtofix'] + '\n'
	if level2protocols.vlan1['mustBeReported'] == True:
		toBeReturned = toBeReturned + level2protocols.vlan1['definition'] + '\n' + level2protocols.vlan1['threatInfo'] + '\n\n' + level2protocols.vlan1['howtofix'] + '\n'
	if level2protocols.unusedports['mustBeReported'] == True:
		toBeReturned = toBeReturned + level2protocols.unusedports['definition'] + '\n' + level2protocols.unusedports['threatInfo'] + '\n\n' + level2protocols.unusedports['howtofix'] + '\n'
	if level2protocols.vtpsecure['mustBeReported'] == True:
		toBeReturned = toBeReturned + level2protocols.vtpsecure['definition'] + '\n' + level2protocols.vtpsecure['threatInfo'] + '\n\n' + level2protocols.vtpsecure['howtofix'] + '\n'
	if level2protocols.bpduguard['mustBeReported'] == True:
		toBeReturned = toBeReturned + level2protocols.bpduguard['definition'] + '\n' + level2protocols.bpduguard['threatInfo'] + '\n\n' + level2protocols.bpduguard['howtofix'] + '\n'
	if level2protocols.stproot['mustBeReported'] == True:
		toBeReturned = toBeReturned + level2protocols.stproot['definition'] + '\n' + level2protocols.stproot['threatInfo'] + '\n\n' + level2protocols.stproot['howtofix'] + '\n'
	if level2protocols.dot1x['mustBeReported'] == True:
		toBeReturned = toBeReturned + level2protocols.dot1x['definition'] + '\n' + level2protocols.dot1x['threatInfo'] + '\n\n' + level2protocols.dot1x['howtofix'] + '\n'

	return toBeReturned

def analyzorNetflow(lines, netflow, ifaceCfg):
	
	for j in range(0, len(ifaceCfg)):
		if searchRegexString(ifaceCfg[j].configuration, '^ip flow (ingress|egress)$') != None:
			netflow.V9securityL2['interfacegress'] = True

	if netflow.V9securityL2['interfacegress'] == True:
		try:
			netflow.V9securityL2['fragoffset'] = searchRegexString(lines, '^ip flow-capture fragment-offset$')
		except AttributeError:
			pass
		try:
			netflow.V9securityL2['icmp'] = searchRegexString(lines, '^ip flow-capture icmp$')
		except AttributeError:
			pass
		try:
			netflow.V9securityL2['ipid'] = searchRegexString(lines, '^ip flow-capture ip-id$')
		except AttributeError:
			pass
		try:
			netflow.V9securityL2['macaddr'] = searchRegexString(lines, '^ip flow-capture mac-addresses$')
		except AttributeError:
			pass
		try:
			netflow.V9securityL2['packetlen'] = searchRegexString(lines, '^ip flow-capture packet-length$')
		except AttributeError:
			pass
		try:
			netflow.V9securityL2['ttl'] = searchRegexString(lines, '^ip flow-capture ttl$')
		except AttributeError:
			pass
		try:
			netflow.V9securityL2['vlid'] = searchRegexString(lines, '^ip flow-capture vlan-id$')
		except AttributeError:
			pass
			
	if ( (netflow.V9securityL2['fragoffset'] == None) or (netflow.V9securityL2['icmp'] == None) or (netflow.V9securityL2['ipid'] == None) or (netflow.V9securityL2['macaddr'] == None) or (netflow.V9securityL2['packetlen'] == None) or (netflow.V9securityL2['ttl'] == None) or (netflow.V9securityL2['vlid'] == None) ):
		netflow.V9securityL2['mustBeReported'] = True

	if netflow.V9securityL2['mustBeReported'] == True:
		items = searchInXml('netflowV9')
		if __builtin__.iosVersion >= 12.42:
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			netflow.V9securityL2 = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}
		else:
			# upgrade to >= 12.42 to get the feature (including L3 fragment-offset)
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			netflow.V9securityL2 = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[4]),
			"cvss": (cvssMetrics)}

	toBeReturned = ''
	if netflow.V9securityL2['mustBeReported'] == True:
		toBeReturned = netflow.V9securityL2['definition'] + '\n' + netflow.V9securityL2['threatInfo'] + '\n\n' + netflow.V9securityL2['howtofix'] + '\n'

	return toBeReturned

def analyzorMulticast(lines, multicast):
	
	if ( (searchRegexString(lines, '^ip pim rp-address .*$') != None) and (searchRegexString(lines, '^ip msdp peer .*$') != None) ):
		
		try:
			multicast.msdp['safilterin'] = searchRegexString(lines, '^ip msdp sa-filter in .*$')
		except AttributeError:
			pass
		try:
			multicast.msdp['safilterout'] = searchRegexString(lines, '^ip msdp sa-filter out .*$')
		except AttributeError:
			pass
		try:
			multicast.msdp['redistributelist'] = searchRegexString(lines, '^ip msdp redistribute list .*$')
		except AttributeError:
			pass
		
		if ( (multicast.msdp['safilterin'] == None) or (multicast.msdp['safilterout'] == None) or (multicast.msdp['redistributelist'] == None) ):
			multicast.msdp['mustBeReported'] = True

		if multicast.msdp['mustBeReported'] == True:
			items = searchInXml('mcastmsdp')
			cvssMetrics = str(calculateCVSS2Score(items[5]))
			multicast.msdp = {
			"mustBeReported": True,
			"fixImpact": (items[0]),
			"definition": (items[1]),
			"threatInfo": (items[2]),			
			"howtofix": (items[3]),
			"cvss": (cvssMetrics)}

	else:
		toBeReturned = 'Multicast MSDP is not configured.'
	if multicast.msdp['mustBeReported'] == True:
		toBeReturned = multicast.msdp['definition'] + '\n' + multicast.msdp['threatInfo'] + '\n\n' + multicast.msdp['howtofix'] + '\n'

	return toBeReturned

