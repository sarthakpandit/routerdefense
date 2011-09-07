# -*- coding: iso-8859-1 -*-

__docformat__ = 'restructuredtext'
__version__ = '$Id$'

import __builtin__
import re
import random
import string
import os
import sys

from xml.dom.minidom import parse

__builtin__.iosVersion = None

def read_cfg(File):
    """Read the show run file."""
    lines = []
    try:
        for line in open(File, 'r'):
            lines.append(line.rstrip())
    except IOError:
        print "The configuration file does not exists."
        exit(1)
    return lines

def check_cfg(lines):
    """Validate that the configuration file is from a Cisco IOS."""
    validatedConfig = 1
    for line in lines:
        if line.startswith('nameif') == True : # PIX/ASA
            validatedConfig = 0
            break
        if line.startswith('feature') == True : # NX-OS
            validatedConfig = 0
            break
    if validatedConfig == 0:
        print "This is not an IOS configuration file."
        exit(1)
    return

class Item:
    """Item class definition."""
    name = None
    fixImpact = None
    definition = None
    threatInfo = None
    howtofix = None
    upgrade = None
    cvssMetric = None

    def __init__(self):
        pass

class Xml2Data:
    """Convert XML to DATA."""
    __currentNode__ = None
    __itemsList__ = None

    def __init__(self):
        self.read_xml()
    def get_root(self):
        if self.__currentNode__ is None:
            self.__currentNode__ = self.xmldoc.documentElement
        return self.__currentNode__

    def get_items(self):
        if self.__itemsList__ is not None:
            return
        self.__itemsList__ = []
        for lines in self.get_root().getElementsByTagName("item"):
            if lines.nodeType == lines.ELEMENT_NODE:
                obj = Item()
                try:
                    obj.name = self.get_text(
                        lines.getElementsByTagName("name")[0])
                    obj.fixImpact = self.get_text(
                        lines.getElementsByTagName("fixImpact")[0])
                    obj.definition = self.get_text(
                        lines.getElementsByTagName("definition")[0])
                    obj.threatInfo = self.get_text(
                        lines.getElementsByTagName("threatInfo")[0])
                    obj.howtofix = self.get_text(
                        lines.getElementsByTagName("howtofix")[0])
                    obj.upgrade = self.get_text(
                        lines.getElementsByTagName("upgrade")[0])
                    obj.cvssMetric = self.get_text(
                        lines.getElementsByTagName("CVSSmetric")[0])
                except xml.dom.DOMException:
                    pass
                self.__itemsList__.append(obj)
        return self.__itemsList__

    def get_text(self, node):
        return node.childNodes[0].nodeValue
    def read_xml(self):
        fsock = open('ciscoObjects.xml')
        self.xmldoc = parse(fsock)
        fsock.close()

def search_xml(name):
    items = []
    xmlFile = Xml2Data()
    nbObjects = len(xmlFile.get_items())
    for x in range(0, nbObjects):
        if name in xmlFile.__itemsList__[x].name:
            items.append(xmlFile.__itemsList__[x].fixImpact)
            items.append(xmlFile.__itemsList__[x].definition)
            items.append(xmlFile.__itemsList__[x].threatInfo)
            items.append(xmlFile.__itemsList__[x].howtofix)
            items.append(xmlFile.__itemsList__[x].upgrade)
            items.append(xmlFile.__itemsList__[x].cvssMetric)
            return items
    return 0

def stripping(line):
    """Left and right strip a specific line."""
    strippedLine = line.lstrip().rstrip()
    return strippedLine

def search_string(iosConfig, search_string):
    """Search a string into a configuration block."""
    stringLookup = None
    if sys.version_info < (2, 5):
        for line in iosConfig:
            if line.lower().rfind(search_string) != -1:
                stringLookup = line
                return stringLookup
    else:
        stringLookup = next(
        (line for line in iosConfig if
        line.lower().rfind(search_string) != -1), None)
        return stringLookup

def search_multi_string(iosConfig, search_string):
    """Search multiple occurence of a string
    into a configuration block.

    """
    stringLookup = None
    stringTable = []
    for line in iosConfig:
        if line.lower().rfind(search_string) != -1:
            stringTable.append(line)
    return stringTable

def search_re_string(iosConfig, search_string):
    """Search a regex matching string into a configuration block."""
    stringLookup = None
    if sys.version_info < (2, 5):
        for line in iosConfig:
            if re.search(search_string, line) is not None:
                stringLookup = line
                return stringLookup
    else:
        stringLookup = next(
        (line for line in iosConfig if
        re.search(search_string, line) is not None), None)
    return stringLookup

def search_re_multi_string(iosConfig, search_string):
    """Search multiple occurence of a regex string
    into a configuration block.

    """
    stringLookup = None
    stringTable = []
    for line in iosConfig:
        stringLookup = re.search(search_string, line)
        if stringLookup is not None:
            stringTable.append(stringLookup.string)
    return stringTable

def search_string_count(iosConfig, search_string):
    """Count occurence of a string."""
    stringCount = 0
    for line in iosConfig:
        if line.rfind(search_string) != -1:
            stringCount = stringCount + 1
    return stringCount

def search_re_string_count(iosConfig, search_string):
    """Count occurence of a regex string."""
    stringCount = 0
    for line in iosConfig:
        if re.search(search_string, line) is not None:
            stringCount = stringCount + 1
    return stringCount

def parse_console(lines):
    """Console port section."""
    consoleTable = []
    for i,v in enumerate(lines):
        if v.rfind('line con 0') != -1:
            lineConLocation = i
            break
    for i in range(lineConLocation + 1, len(lines)):
        if (not lines[i].startswith("!") and
        not lines[i].startswith("line")):
            consoleTable.append(stripping(lines[i]))
        else:
            break
    return consoleTable

def parse_aux(lines):
    """Aux port section."""
    auxTable = []
    lineAuxLocation = 0
    for i,v in enumerate(lines):
        if v.rfind('line aux 0') != -1:
            lineAuxLocation = i
            break
    if lineAuxLocation != 0:
        for i in range(lineAuxLocation + 1, len(lines)):
            if (not lines[i].startswith("!") and
            not lines[i].startswith("line")):
                auxTable.append(stripping(lines[i]))
            else:
                break

    return auxTable

def parse_vty(lines):
    """VTY section."""
    vtyTable = []
    lineVtyLocation = []
    for i,v in enumerate(lines):
        if v.rfind('line vty') != -1:
            lineVtyLocation.append(i)
            vtyTable.append([stripping(lines[i])])
    for j in range( 0, len(lineVtyLocation) ):
        for k in range(lineVtyLocation[j] + 1, len(lines)):
            if (lines[k].startswith(" ") or
            not lines[k].startswith("!") and
            not lines[k].startswith("line")):
                vtyTable[j].append(stripping(lines[k]))
            else:
                break
    return vtyTable

def parse_extd_acl(aclname):
    """Parse extended ACL."""
    table = []
    location = []
    for i,v in enumerate(__builtin__.wholeconfig):
        if v.rfind(aclname) != -1:
            location.append(i)
            table.append([stripping(__builtin__.wholeconfig[i])])
    for j in range( 0, len(location) ):
        for k in range(location[j] + 1, len(__builtin__.wholeconfig)):
            if not __builtin__.wholeconfig[k].startswith("!"):
                table[j].append(stripping(__builtin__.wholeconfig[k]))
            else:
                break
    return table


def parse_motd(lines):
    """Parse the MOTD banner."""
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

def parse_exec_banner(lines):
    """Parse the EXEC banner."""
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

def parse_login_banner(lines):
    """Parse the LOGIN banner."""
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

def stdout_content(definition, threatInfo, howtofix, impact, cvss):
    """Format the reporting content for stdout."""
    str = ''
    str = """
    => What: """ + definition + """
    => Threat: """ + threatInfo + """
    => Patch impact: """ + impact + """
    => Score: """ + cvss + """/10
    => How to fix: \n    """ + howtofix

    return str

def stdout_banner(categoryname):
    """Print the category banner section."""
    return '=[ ' + categoryname

def stdout_category_banner(categoryname):
    """Print the category sections definitions."""
    catname = ''
    if categoryname == 'ManagementPlane':
        catname = 'Management plane'
        catdef = """The management plane consists of functions \
that achieve the management goals of the network. \
This includes interactive management sessions using SSH, \
as well as statistics-gathering with SNMP or NetFlow. \
When you consider the security of a network device, \
it is critical that the management plane be protected. \
If a security incident is able to undermine the functions of \
the management plane, it can be impossible for you to \
recover or stabilize the network.

"""
    if categoryname == 'ControlPlane':
        catname = 'Control plane'
        catdef = """Control plane functions consist of the protocols \
and processes that communicate between network devices to move data \
from source to destination. This includes routing protocols such as \
the Border Gateway Protocol, as well as protocols like ICMP and \
the Resource Reservation Protocol (RSVP).

"""
    if categoryname == 'DataPlane':
        catname = 'Data plane'
        catdef = """Although the data plane is responsible for \
moving data from source to destination, within the context of \
security, the data plane is the least important of the three planes. \
It is for this reason that when securing a network device it is \
important to protect the management and control planes \
in preference over the data plane.

"""
    return '=[' + catname + ']=' + catdef


def cvss_score(metrics):
    """Calculate the CVSS score."""
    metrics = metrics.split('/')
    accessvector = str(metrics[0]).split(':')[1]
    if accessvector == "L":
        AV = float(0.395)
    elif accessvector == "A":
        AV = float(0.646)
    elif accessvector == "N":
        AV = float(1.0)
    else:
        raise Exception
    accesscomplexity = str(metrics[1]).split(':')[1]
    if accesscomplexity == "H":
        AC = float(0.35)
    elif accesscomplexity == "M":
        AC = float(0.61)
    elif accesscomplexity == "L":
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
    confidentialityimpact = str(metrics[3]).split(':')[1]
    if confidentialityimpact == "N":
        CI = float(0.0)
    elif confidentialityimpact == "P":
        CI = float(0.275)
    elif confidentialityimpact == "C":
        CI = float(0.660)
    else:
        raise Exception
    integrityimpact = str(metrics[4]).split(':')[1]
    if integrityimpact == "N":
        II = float(0.0)
    elif integrityimpact == "P":
        II = float(0.275)
    elif integrityimpact == "C":
        II = float(0.660)
    else:
        raise Exception
    availabilityimpact = str(metrics[5]).split(':')[1]
    if availabilityimpact == "N":
        AI = float(0.0)
    elif availabilityimpact == "P":
        AI = float(0.275)
    elif availabilityimpact == "C":
        AI = float(0.660)
    else:
        raise Exception
    impact = 10.41*(1-(1-CI)*(1-II)*(1-AI))
    exploitability = 20*AV*AC*AU
    impacter = set_impacter(impact)
    basescore = round(float(
    (0.6 * impact + 0.4 * exploitability -1.5)
    * impacter),1)
    score = basescore
    return score

def set_impacter(impact):
    """Calculate the CVSS impacter value."""
    if impact == 0:
        value = float(0)
    else:
        value = float(1.176)
    return value

def snmp_community_complexity(name):
    """Define if the SNMP community is complex enough."""
    if len(name) <= 7:
        return False
    else:
        if name == '<removed>':
            return True
        if not re.findall('[0-9]', name):
            return False
        else:
            if not re.findall('[A-Z]', name):
                return False
            else:
                if not re.findall('[a-z]', name):
                    return False
                else:
                    for c in name:
                        if c in string.punctuation:
                            return True
                    return False

def dotted_netmask(netmask):
    """Convert dotted notation of a /xx netmask."""
    bits = 0
    for i in xrange(32-int(netmask),32):
        bits |= (1 << i)
    return "%d.%d.%d.%d" % (
    (bits & 0xff000000) >> 24,
    (bits & 0xff0000) >> 16,
    (bits & 0xff00) >> 8 ,
    (bits & 0xff)
    )

def netmask_wildcard(netmask):
    """Convert a dotted netmask to a dotted wildcard mask."""
    inversedByte = list()
    bytes = netmask.split('.')
    for byte in bytes:
        inversedByte.append(255 - int(byte))
    return "%d.%d.%d.%d" % (
    inversedByte[0],
    inversedByte[1],
    inversedByte[2],
    inversedByte[3]
    )

def network_address(address, mask):
    """Output the network address from an address+mask."""
    Addressbytes = address.split('.')
    Maskbytes = mask.split('.')
    return "%d.%d.%d.%d" % (
    int(Addressbytes[0]) & int(Maskbytes[0]),
    int(Addressbytes[1]) & int(Maskbytes[1]),
    int(Addressbytes[2]) & int(Maskbytes[2]),
    int(Addressbytes[3]) & int(Maskbytes[3])
    )

def network_reverse_address(address, inversedmask):
    """Output the network address from an address+wildcard mask."""
    Addressbytes = address.split('.')
    Maskbytes = inversedmask.split('.')
    count = 0
    for byte in Maskbytes:
        Maskbytes[count] = int(byte) + 255
        count = count + 1
    return "%d.%d.%d.%d" % (
    int(Addressbytes[0]) & int(Maskbytes[0]),
    int(Addressbytes[1]) & int(Maskbytes[1]),
    int(Addressbytes[2]) & int(Maskbytes[2]),
    int(Addressbytes[3]) & int(Maskbytes[3]))

def check_std_acl(lines, aclnumber):
    """Check if the standard ACL is found within the block."""
    if __builtin__.ipv4_mgmt_outbound is None:
        return False
    acl = 'access-list ' + aclnumber.strip()  + ' permit'
    matchACL = search_string(lines, acl)
    if matchACL is not None:
        network = matchACL.split(' ')[3]
        try:
            mask = matchACL.split(' ')[4]
        except IndexError:
            mask = "0.0.0.0"
        net = network_reverse_address(network, mask)
        for entry in __builtin__.ipv4_mgmt_outbound:
            if net == entry[4]:
                return True
    return False

def check_extd_acl(lines, aclumber):
    """Check if the extended ACL is found within the block."""
    if __builtin__.ipv4_mgmt_inbound is None:
        return False
    acl = 'ip access-list extended ' + aclumber.strip()
    specificacl = parse_extd_acl(acl)
    matchACL = search_multi_string(specificacl[0], 'permit')
    validated= False

    if matchACL is not None:
        for ace in matchACL:
            network = ace.split(' ')[2]
            if network == 'host':
                mask = "0.0.0.0"
                net = ace.split(' ')[3]
            elif network == 'any':
                pass
            else:
                mask = ace.split(' ')[3]
                net = network_reverse_address(network, mask)

        for entry in __builtin__.ipv4_mgmt_inbound:
            if net == entry[4]:
                validated = True
            else:
                validated = False
    return validated

def populate_ifaces(lines, interfaces):
    """Populate a table with each line of an interface configuration."""
    ifacecfg = []
    recordcfg = False
    ifaceindex = 0
    for line in lines:
        if line.lower().startswith('interface'):
            ifacename = line.split(' ')[1]
            ifacecfg.append(interfaces.add_if('interface', ifacename))
            recordcfg = True
        if recordcfg == True and line.startswith('!'):
            recordcfg = False
            ifaceindex = ifaceindex + 1
        elif recordcfg == True and line.startswith('!') == False:
            if line.lower().startswith('interface') == False:
                ifacecfg[ifaceindex].configuration.append(line.strip())
    return ifacecfg

def populate_acl_v4(lines, acls):
    """Populate a table with each line of a standard IPv4 ACL."""
    acl = []
    recordcfg = False
    index = 0
    for line in lines:
        if line.lower().startswith('ip access-list'):
            aclname = line.split(' ')[3]
            acl.append(acls.add('aclv4', aclname))
            recordcfg = True
        elif line.lower().startswith('access-list'):
            aclname = line.split(' ')[2]
            acl.append(acls.add('aclv4', aclname))
            recordcfg = True
        if recordcfg == True and line.startswith('!'):
            recordcfg = False
            index = index + 1
        elif recordcfg == True and line.startswith('!') == False:
            if line.lower().startswith('ip access-list') == False:
                acl[index].configuration.append(line.strip())
            if line.lower().startswith('access-list') == False:
                acl[index].configuration.append(line.strip())
    return acl

def populate_acl_v6(lines, acls):
    """Populate a table with each line of a standard IPv6 ACL."""
    acl = []
    recordcfg = False
    index = 0
    for line in lines:
        if line.lower().startswith('ipv6 access-list'):
            aclName = line.split(' ')[2]
            acl.append(acls.add('aclv6', aclName))
            recordcfg = True
        if recordcfg == True and line.startswith('!'):
            recordcfg = False
            index = index + 1
        elif recordcfg == True and line.startswith('!') == False:
            if line.lower().startswith('ipv6 access-list') == False:
                acl[index].configuration.append(line.strip())
    return acl











