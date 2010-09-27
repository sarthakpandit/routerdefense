#!/usr/bin/python
import sys 
from metrics import *
from analyzor import *
from common import *
lines = readCfg(sys.argv[1])
Interfaces = IFSmetrics()
ControlPlaneAudit = CPmetrics()
multicast = ControlPlaneAudit.addMetric('multicast')
print analyzorMulticast(lines, multicast)


