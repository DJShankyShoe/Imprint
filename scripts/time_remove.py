#!/usr/bin/python3

import os
import sys
import time

var = sys.argv[1]
time.sleep(5)

try:
    os.remove(var)
    pass
except FileNotFoundError:
    pass
