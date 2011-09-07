# -*- coding: iso-8859-1 -*-

__docformat__ = 'restructuredtext'
__version__ = '$Id$'

import __builtin__
from routerdefense.common import *

from xml import *

def engine_multicast(lines, multicast):
    """Multicast configuration assessment."""

    if ( (search_re_string(lines, '^ip pim rp-address .*$') is not None) and (search_re_string(lines, '^ip msdp peer .*$') is not None) ):

        try:
            multicast.msdp['safilterin'] = search_re_string(lines, '^ip msdp sa-filter in .*$')
        except AttributeError:
            pass
        try:
            multicast.msdp['safilterout'] = search_re_string(lines, '^ip msdp sa-filter out .*$')
        except AttributeError:
            pass
        try:
            multicast.msdp['redistributelist'] = search_re_string(lines, '^ip msdp redistribute list .*$')
        except AttributeError:
            pass

        if ( (multicast.msdp['safilterin'] is None) or (multicast.msdp['safilterout'] is None) or (multicast.msdp['redistributelist'] is None) ):
            multicast.msdp['must_report'] = True

        if multicast.msdp['must_report'] == True:
            items = search_xml('mcastmsdp')
            cvssMetrics = str(cvss_score(items[5]))
            multicast.msdp = {
            "must_report": True,
            "fixImpact": (items[0]),
            "definition": (items[1]),
            "threatInfo": (items[2]),
            "howtofix": (items[3]),
            "cvss": (cvssMetrics)}

    else:
        toBeReturned = 'Multicast MSDP is not configured.'
    if multicast.msdp['must_report'] == True:
        toBeReturned = multicast.msdp['definition'] + '\n' + multicast.msdp['threatInfo'] + '\n\n' + multicast.msdp['howtofix'] + '\n'

    return toBeReturned
