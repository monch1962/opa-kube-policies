#!/usr/bin/env python
import sys
import yaml
import json
y = yaml.safe_load(sys.stdin.read())
print(json.dumps(y, indent=2))
