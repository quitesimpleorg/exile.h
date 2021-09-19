#!/usr/bin/python
import sys
import re
if len(sys.argv) < 2:
	print("Usage: gengroup groupfile")
	sys.exit(1)
fd = open(sys.argv[1], "r")

lines = fd.read().splitlines()

groupnames = set()
ifndef = dict()	

def print_ifndefs():
	for name in ifndef:
		print("#ifndef __NR_%s" % name)
		print("#define __NR_%s %s" % (name, ifndef[name]))
		print("#endif")

def print_defines(names):
	names = sorted(names)
	i = 0
	for name in names:
		define = "#define %s ((uint64_t)1<<%s)" % (name, i)
		print(define)
		i = i + 1

for line in lines:
	if line[0] == '#':
		continue

	splitted = line.split(' ')
	if len(splitted) < 2:
		print("Misformated line:", line)
		sys.exit(1)

	currentsyscall = splitted[0]
	currentgroups = splitted[1].split(',')
	
	flags = splitted[2] if len(splitted) > 2 else ""
	if any( not s or s.isspace() for s in currentgroups ):
		print("Misformated line (empty values):", line)
		sys.exit(1)
	groupnames.update(currentgroups)
	
	genifndef = re.match(r"genifndef\((\d+)*\)", flags)
	if genifndef:
		ifndef[currentsyscall] = genifndef.groups(1)[0]
	
	array_line = "{QSSB_SYS(%s), %s}," % (currentsyscall, '|'.join(currentgroups))
	print(array_line)

print_ifndefs()
print_defines(groupnames)

