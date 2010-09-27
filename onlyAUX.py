#!/usr/bin/python
import sys 
from metrics import *
from analyzor import *
from common import *
lines = readCfg(sys.argv[1])
auxCfg = parseAux(lines)
ManagementPlaneAudit = metrics()
aux = ManagementPlaneAudit.addMetric('auxPort')
analyzorAux(auxCfg,aux)
print analyzorAux(auxCfg,aux)

