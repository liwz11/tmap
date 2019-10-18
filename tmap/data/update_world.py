import re

f = open("world-110m.json", "r")
content = f.read()
f.close()

f = open("world-country-names.tsv", "r")
lines = f.readlines()
f.close()

d = {}
for line in lines:
	line = line.replace("\n", "")
	tmp = line.split("\t")
	d[tmp[0]] = tmp[1]

p = re.compile(r'(,\"id\":([-0-9]*),)')
for m in p.finditer(content):
	#print m.group(1), m.group(2)
	name = ""
	if d.has_key(m.group(2)):
		name = d[m.group(2)]
	content = content.replace(m.group(1), m.group(1) + "\"properties\":{\"name\":\"" + name + "\"},")

f = open("world-110m.json", "w")
f.write(content)
f.close()