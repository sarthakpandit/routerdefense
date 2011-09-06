#!/usr/bin/python
import sys 
from metrics import *
from analyzor import *
from common import *
lines = readCfg(sys.argv[1])
consoleCfg = parseConsole(lines)
ManagementPlaneAudit = metrics()
console = ManagementPlaneAudit.addMetric('consolePort')
print analyzorConsole(consoleCfg, console, lines)

