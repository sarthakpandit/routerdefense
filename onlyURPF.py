#!/usr/bin/python
import sys 
from metrics import *
from analyzor import *
from common import *
lines = readCfg(sys.argv[1])
Interfaces = IFSmetrics()
ifaceCfg = populateInterfaces(lines,Interfaces)
DataPlaneAudit = DPmetrics()
urpf = DataPlaneAudit.addMetric('urpf')
print analyzorURPF(lines, urpf, ifaceCfg)

