# -*- coding: iso-8859-15 -*-

import __builtin__
import re
import random
import string
import os
import sys
__builtin__.iosVersion = None
from xml.dom.minidom import parse

def readCfg(File):
	try:
		config = open(File, 'r')
		lines = []
		for line in config:
			lines.append(line.lstrip())
		config.close()
	except IOError:
		print "The configuration file does not exists."
		exit(1)
	return lines

def readTemplate(File):
	try:
		config = open(File, 'r')
	except IOError:
		print "The template file does not exists."
		exit(1)		
	templateLines = []
	templateLines.append('')
	templateLines.append('')
	templateLines.append('')
	templateLines.append('')
	templateLines.append('')
	templateLines.append('')
	templateLines.append('')
	templateLines.append('')
	templateLines.append('')
	templateLines.append('')
	templateLines.append('')
	templateLines.append('')

	lines = config.readlines()
	for i in range(0,len(lines)):
		if ( (lines[i].startswith('#') == False) and (len(lines[i]) >=3) ):
			if lines[i].strip().split('=',1)[0] == 'iosversion':
				templateLines[0] = lines[i].strip().split('=',1)[1]
			if lines[i].strip().split('=',1)[0] == 'outputFormat':
				if re.search('(^stdout$|^csv$|^html$|^pdf$)',lines[i].strip().split('=',1)[1].lower()) != None:
					templateLines[1] = lines[i].strip().split('=',1)[1].lower()
				else:
					printTmplError(lines[i], i)
					exit(1)
			if lines[i].strip().split('=',1)[0] == 'outputFile':
				if os.path.exists(os.path.dirname(lines[i].strip().split('=',1)[1])):
					templateLines[2] = lines[i].strip().split('=',1)[1]
				else:
					printTmplError(lines[i], i)
					exit(1)	
			if lines[i].strip().split('=',1)[0] == 'deviceType':
				if re.search('(^router$|^switch$|^both$)',lines[i].strip().split('=',1)[1].lower()) != None:
					templateLines[3] = lines[i].strip().split('=',1)[1].lower()
				else:
					printTmplError(lines[i], i)
					exit(1)

			if lines[i].strip().split('=',1)[0] == 'IPv4trustedBGPpeers':
				if re.search('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',lines[i].strip().split('=',1)[1]) != None:
					templateLines[4] = lines[i].strip().split('=',1)[1]
				elif not lines[i].strip().split('=',1)[1]:
					templateLines[4] = '' 
				else:
					printTmplError(lines[i], i)
					exit(1)															
			if lines[i].strip().split('=',1)[0] == 'IPv4localEBGPaddress':
				if re.search('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',lines[i].strip().split('=',1)[1]) != None:
					templateLines[5] = lines[i].strip().split('=',1)[1]
				elif not lines[i].strip().split('=',1)[1]:
					templateLines[5] = '' 
				else:
					printTmplError(lines[i], i)
					exit(1)															
			if lines[i].strip().split('=',1)[0] == 'IPv4trustedManagementStations':
				templateLines[6] = lines[i].strip().split('=',1)[1]
			if lines[i].strip().split('=',1)[0] == 'IPv4trustedNetManagementServers':
				templateLines[7] = lines[i].strip().split('=',1)[1]
			if lines[i].strip().split('=',1)[0] == 'IPv4trustedNetworks':
				templateLines[8] = lines[i].strip().split('=',1)[1]
			if lines[i].strip().split('=',1)[0] == 'IPv4infrastructureAddressSpace':
				templateLines[9] = lines[i].strip().split('=',1)[1]																

			if lines[i].strip().split('=',1)[0] == 'macro':
				if re.search('(^(?i)Yes$|^No$)',lines[i].strip().split('=',1)[1].lower()) != None:
					templateLines[10] = lines[i].strip().split('=',1)[1].lower()
				else:
					printTmplError(lines[i], i)
					exit(1)

			if lines[i].strip().split('=',1)[0] == 'IPv6TrustedPrefixes':
					templateLines[11] = lines[i].strip().split('=',1)[1].lower()

	config.close()
	if templateLines[-1] == '# NOTCONFIGURED -- Remove me to run the tool':
		exit('Please configure the configuration file before running the tool.')

	return templateLines

def printTmplError(line, number):
	print "Error while reading template file line number "+ str((number+1))+ ": " 
	print line
	print "Please fix the template file before running RouterDefense."
	return

class unique_object:

	name = None
	fixImpact = None
	definition = None
	threatInfo = None
	howtofix = None
	upgrade = None
	cvssMetric = None
    
	def __init__(self):
		pass

class xformXML2Data:
	
	__currentNode__ = None
	__uniqueObjectsList__ = None
	
	def __init__(self):
		self.readXml()
	def getRootElement(self):
	  	if self.__currentNode__ == None:
	  		self.__currentNode__ = self.xmldoc.documentElement
	  	return self.__currentNode__	

	def getUniqueObjects(self):
		if self.__uniqueObjectsList__ != None:
			return
		self.__uniqueObjectsList__ = []
		for lines in self.getRootElement().getElementsByTagName("unique_object"):
			if lines.nodeType == lines.ELEMENT_NODE:
				obj = unique_object()
				try:
					obj.name = self.getText(lines.getElementsByTagName("name")[0])
					obj.fixImpact = self.getText(lines.getElementsByTagName("fixImpact")[0])
					obj.definition = self.getText(lines.getElementsByTagName("definition")[0])
					obj.threatInfo = self.getText(lines.getElementsByTagName("threatInfo")[0])
					obj.howtofix = self.getText(lines.getElementsByTagName("howtofix")[0])
					obj.upgrade = self.getText(lines.getElementsByTagName("upgrade")[0])
					obj.cvssMetric = self.getText(lines.getElementsByTagName("CVSSmetric")[0])
				except:
					pass
				self.__uniqueObjectsList__.append(obj)
		return self.__uniqueObjectsList__	
	
	def getText(self, node):
		return node.childNodes[0].nodeValue	
	def readXml(self):
		fsock = open('ciscoObjects.xml')
		self.xmldoc = parse(fsock) 
		fsock.close()                 

def searchInXml(name):
	items = []
	xmlFile = xformXML2Data()
	nbObjects = len(xmlFile.getUniqueObjects())
	for x in range(0, nbObjects):
		if name in xmlFile.__uniqueObjectsList__[x].name:
			items.append(xmlFile.__uniqueObjectsList__[x].fixImpact)
			items.append(xmlFile.__uniqueObjectsList__[x].definition)
			items.append(xmlFile.__uniqueObjectsList__[x].threatInfo)
			items.append(xmlFile.__uniqueObjectsList__[x].howtofix)
			items.append(xmlFile.__uniqueObjectsList__[x].upgrade)
			items.append(xmlFile.__uniqueObjectsList__[x].cvssMetric)
			return items
	return 0	

def removeString(line):
	stringFreeLine = re.sub("[^0-9\.]", "", line)
	if stringFreeLine.count('.') > 1:
		stringFreeLine = stringFreeLine.split('.')[0] + '.' + stringFreeLine.split('.')[1]
	return stringFreeLine

def stripping(line):
	strippedLine = line.lstrip().rstrip()
	return strippedLine

def searchString(iosConfig, searchString):
	stringLookup = None
	if sys.version_info < (2, 5):
		for line in iosConfig:
			if line.lower().rfind(searchString) != -1:
				stringLookup = line
				return stringLookup
	else:
		try:
			stringLookup = next((line for line in iosConfig if line.lower().rfind(searchString) != -1), None)
		except:
			raise "FAIL during the searchString() function."
		return stringLookup

def searchRegexString(iosConfig, searchString):
	stringLookup = None
	if sys.version_info < (2, 5):
		for line in iosConfig:
			if re.search(searchString, line) != None:
				stringLookup = line
				return stringLookup	
	else:
		try:
			stringLookup = next((line for line in iosConfig if re.search(searchString, line) != None), None)
		except:
			raise "FAIL during the searchRegexString() function."
	return stringLookup

def searchRegexMultiString(iosConfig, searchString):
	stringLookup = None
	stringTable = []
	try:
		for line in iosConfig:
			stringLookup = re.search(searchString, line)
			if stringLookup != None:
				stringTable.append(stringLookup.string)
	except:
		print "ECHEC"
	return stringTable

def searchStringCount(iosConfig, searchString):
	stringCount = 0
	for line in iosConfig:
		if line.rfind(searchString) != -1:
			stringCount = stringCount + 1
	return stringCount

def searchRegexStringCount(iosConfig, searchString):
	stringCount = 0
	for line in iosConfig:
		if re.search(searchString, line) != None:
			stringCount = stringCount + 1
	return stringCount	

def parseConsole(lines):
	consoleTable = []
	for i,v in enumerate(lines):
		if v.rfind('line con 0') != -1:
			lineConLocation = i
			break
	for i in range(lineConLocation + 1, len(lines)):
		if lines[i].startswith(" "):
			consoleTable.append(stripping(lines[i]))
		else:
			break
	
	return consoleTable

def parseAux(lines):
	auxTable = []
	lineAuxLocation = 0
	for i,v in enumerate(lines):
		if v.rfind('line aux 0') != -1:
			lineAuxLocation = i
			break
	if lineAuxLocation != 0:	
		for i in range(lineAuxLocation + 1, len(lines)):
			if lines[i].startswith(" "):
				auxTable.append(stripping(lines[i]))
			else:
				break
	
	return auxTable

def parseVty(lines):
	vtyTable = []
	lineVtyLocation = []
	for i,v in enumerate(lines):
		if v.rfind('line vty') != -1:
			lineVtyLocation.append(i)
			vtyTable.append([stripping(lines[i])])
	for j in range( 0, len(lineVtyLocation) ):
		for k in range(lineVtyLocation[j] + 1, len(lines)):
			if lines[k].startswith(" "):
				vtyTable[j].append(stripping(lines[k]))
			else:
				break
	return vtyTable

def parseBannerMOTD(lines):
	bannerTable = []
	bannerStartLocation = 0
	for i,v in enumerate(lines):
		if v.rfind('banner motd') != -1:
			bannerStartLocation = i
			break
	if bannerStartLocation == 0:
		return bannerTable
	else:	
		for i in range(bannerStartLocation + 1, len(lines)):
			if not lines[i].startswith("!"):
				bannerTable.append(stripping(lines[i]))
			else:
				break
	
	return bannerTable

def parseBannerEXEC(lines):
	bannerTable = []
	bannerStartLocation = 0
	for i,v in enumerate(lines):
		if v.rfind('banner exec') != -1:
			bannerStartLocation = i
			break
	if bannerStartLocation == 0:
		return bannerTable
	else:	
		for i in range(bannerStartLocation + 1, len(lines)):
			if not lines[i].startswith("!"):
				bannerTable.append(stripping(lines[i]))
			else:
				break
	
	return bannerTable

def parseBannerLOGIN(lines):
	bannerTable = []
	bannerStartLocation = 0
	for i,v in enumerate(lines):
		if v.rfind('banner login') != -1:
			bannerStartLocation = i
			break
	if bannerStartLocation == 0:
		return bannerTable
	else:	
		for i in range(bannerStartLocation + 1, len(lines)):
			if not lines[i].startswith("!"):
				bannerTable.append(stripping(lines[i]))
			else:
				break
	
	return bannerTable

def formatStdoutContent(definition, threatInfo, howtofix, patchImpact, cvss):
	
	outputContent = ''
	outputContent = """
    => What: """ + definition + """
    => Threat: """ + threatInfo + """
    => Patch impact: """ + patchImpact + """
    => Score: """ + cvss + """/10
    => How to fix: \n    """ + howtofix	 	
	
	return outputContent

def createStdoutBanner(categoryName):

	catNameOutput = categoryName
					
	outputBanner = """
=[ """ + catNameOutput
	return outputBanner

def createStdoutCatBanner(categoryName):

	catNameOutput = ''
	if categoryName == 'ManagementPlane':
		catNameOutput = 'Management plane'
		catDefinitionOutput = """The management plane consists of functions that achieve the management goals of the network.
This includes interactive management sessions using SSH, as well as statistics-gathering with SNMP or NetFlow.
When you consider the security of a network device, it is critical that the management plane be protected.
If a security incident is able to undermine the functions of the management plane, it can be impossible for you to recover or stabilize the network."""
	if categoryName == 'ControlPlane':
		catNameOutput = 'Control plane'
		catDefinitionOutput = """Control plane functions consist of the protocols and processes that communicate between network devices to move data from source to destination.
This includes routing protocols such as the Border Gateway Protocol, as well as protocols like ICMP and the Resource Reservation Protocol (RSVP)."""
	if categoryName == 'DataPlane':
		catNameOutput = 'Data plane'
		catDefinitionOutput = """Although the data plane is responsible for moving data from source to destination, within the context of security, the data plane is the least important of the three planes.
It is for this reason that when securing a network device it is important to protect the management and control planes in preference over the data plane."""	
		
	outputBanner = """
=[ """ + catNameOutput + """ ]=
""" + catDefinitionOutput	
	return outputBanner


def calculateCVSS2Score(metrics):
	
	metrics = metrics.split('/')
	accessVector = str(metrics[0]).split(':')[1]
	if accessVector == "L":
		AV = float(0.395)
	elif accessVector == "A":
		AV = float(0.646)
	elif accessVector == "N":
		AV = float(1.0)
	else:
		raise Exception		
	accessComplexity = str(metrics[1]).split(':')[1]
	if accessComplexity == "H":
		AC = float(0.35)
	elif accessComplexity == "M":
		AC = float(0.61)
	elif accessComplexity == "L":
		AC = float(0.71)
	else:
		raise Exception		
	authentication = str(metrics[2]).split(':')[1]
	if authentication == "N":
		AU = float(0.704)
	elif authentication == "S":
		AU = float(0.56)
	elif authentication == "M":
		AU = float(0.45)
	else:
		raise Exception
	confidentialityImpact = str(metrics[3]).split(':')[1]
	if confidentialityImpact == "N":
		CI = float(0.0)
	elif confidentialityImpact == "P":
		CI = float(0.275)
	elif confidentialityImpact == "C":
		CI = float(0.660)
	else:
		raise Exception	
	integrityImpact = str(metrics[4]).split(':')[1]
	if integrityImpact == "N":
		II = float(0.0)
	elif integrityImpact == "P":
		II = float(0.275)
	elif integrityImpact == "C":
		II = float(0.660)
	else:
		raise Exception	
	availabilityImpact = str(metrics[5]).split(':')[1]
	if availabilityImpact == "N":
		AI = float(0.0)
	elif availabilityImpact == "P":
		AI = float(0.275)
	elif availabilityImpact == "C":
		AI = float(0.660)
	else:
		raise Exception	
	Impact = 10.41*(1-(1-CI)*(1-II)*(1-AI))
	Exploitability = 20*AV*AC*AU
	impacter = setImpacter(Impact)
	BaseScore = round(float((0.6 * Impact + 0.4 * Exploitability -1.5) * impacter),1)
	CVSSscore = BaseScore
	return CVSSscore

def setImpacter(Impact):
	if Impact == 0: 
		impacterValue = float(0)
	else:
		impacterValue = float(1.176)
	return impacterValue

def SNMPsecureCommunity(communityName):
	if len(communityName) <= 7:
		return False
	else:
		if not re.findall('[0-9]', communityName):
			return False
		else:
			if not re.findall('[A-Z]', communityName):
				return False
			else:
				if not re.findall('[a-z]', communityName):
					return False
				else:
					for c in communityName:
						if c in string.punctuation:
							return True
					return False				

def dotted2Netmask(netmask):
	bits = 0
	for i in xrange(32-int(netmask),32):
		bits |= (1 << i)
	return "%d.%d.%d.%d" % ((bits & 0xff000000) >> 24, (bits & 0xff0000) >> 16, (bits & 0xff00) >> 8 , (bits & 0xff))

def netmask2wildcard(netmask):
	inversedByte = list()
	bytes = netmask.split('.')
	for byte in bytes:
		inversedByte.append(255 - int(byte))
	return "%d.%d.%d.%d" % (inversedByte[0], inversedByte[1], inversedByte[2], inversedByte[3])	

def networkAddress(address, mask):
	Addressbytes = address.split('.')
	Maskbytes = mask.split('.')
	return "%d.%d.%d.%d" % (int(Addressbytes[0]) & int(Maskbytes[0]), int(Addressbytes[1]) & int(Maskbytes[1]), int(Addressbytes[2]) & int(Maskbytes[2]), int(Addressbytes[3]) & int(Maskbytes[3]))	

def networkReverseAddress(address, inversedmask):
	Addressbytes = address.split('.')
	Maskbytes = inversedmask.split('.')
	count = 0
	for byte in Maskbytes:
		Maskbytes[count] = int(byte) + 255
		count = count + 1
	return "%d.%d.%d.%d" % (int(Addressbytes[0]) & int(Maskbytes[0]), int(Addressbytes[1]) & int(Maskbytes[1]), int(Addressbytes[2]) & int(Maskbytes[2]), int(Addressbytes[3]) & int(Maskbytes[3]))	
			
def checkStdACL(lines, accessListNumber):
	accessList = 'access-list ' + accessListNumber.strip()  + ' permit'
	matchACL = searchString(lines, accessList)
	if matchACL != None:
		network = matchACL.split(' ')[3]
		try:
			mask = matchACL.split(' ')[4]
		except IndexError:
			mask = "0.0.0.0"
		net = networkReverseAddress(network, mask)
		for entry in __builtin__.IPv4trustedNetManagementServers:
			if net == entry[4]:
				return True
	return False

def populateInterfaces(lines, Interfaces):
	ifaceCfg = []
	recordCfg = False
	ifaceIndex = 0
	for line in lines:
		if line.lower().startswith('interface'):
			ifaceName = line.split(' ')[1]
			ifaceCfg.append(Interfaces.addInterface('interface', ifaceName))
			recordCfg = True 
		if recordCfg == True and line.startswith('!'):
			recordCfg = False
			ifaceIndex = ifaceIndex + 1
		elif recordCfg == True and line.startswith('!') == False:
			if line.lower().startswith('interface') == False:	
				ifaceCfg[ifaceIndex].configuration.append(line.strip())
	return ifaceCfg

def populateACLv4(lines, AclsV4):
	aclIPv4 = []
	recordCfg = False
	aclIndex = 0
	for line in lines:
		if line.lower().startswith('ip access-list'):
			aclName = line.split(' ')[3]
			aclIPv4.append(AclsV4.addInterface('aclv4', aclName))
			recordCfg = True
		elif line.lower().startswith('access-list'):
			aclName = line.split(' ')[2]
			aclIPv4.append(AclsV4.addInterface('aclv4', aclName))
			recordCfg = True		
		if recordCfg == True and line.startswith('!'):
			recordCfg = False
			aclIndex = aclIndex + 1
		elif recordCfg == True and line.startswith('!') == False:
			if line.lower().startswith('ip access-list') == False:	
				aclIPv4[aclIndex].configuration.append(line.strip())
			if line.lower().startswith('access-list') == False:	
				aclIPv4[aclIndex].configuration.append(line.strip())
	return aclIPv4

def populateACLv6(lines, AclsV6):

	aclIPv6 = []
	recordCfg = False
	aclIndex = 0
	for line in lines:
		if line.lower().startswith('ipv6 access-list'):
			aclName = line.split(' ')[2]
			aclIPv6.append(AclsV6.addInterface('aclv6', aclName))
			recordCfg = True 
		if recordCfg == True and line.startswith('!'):
			recordCfg = False
			aclIndex = aclIndex + 1
		elif recordCfg == True and line.startswith('!') == False:
			if line.lower().startswith('ipv6 access-list') == False:	
				aclIPv6[aclIndex].configuration.append(line.strip())
	return aclIPv6

	









