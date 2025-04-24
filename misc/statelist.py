table = [
	(1<<6, "DIED"),
	(1<<5, "RECV"),
	(1<<4, "SEND"),
	(1<<3, "RECV_STARTED"),
	(1<<2, "SEND_STARTED"),
	(1<<1, "READY"),
	(1<<0, "CLOSE"),
]

outstates = [
	"STATUS",
	"HEADER",
	"BODY",
]

i = 0
k = 0
while i < 2**len(table):

	tags = []
	for entry in table:
		if i & entry[0]:
			tags.append(entry[1])

	statestr = "|".join(tags)

	if ("DIED" in tags) and ("READY" in tags):
		i += 1
		continue

	if ("READY" not in tags) and ("DIED" not in tags) and ("SEND" not in tags) and ("RECV" not in tags):
		i += 1
		continue

	if ("READY" in tags) and ("CLOSE" in tags):
		i += 1
		continue

	if ("CLOSE" in tags) and ("SEND" not in tags):
		i += 1
		continue

	if (("CLOSE" in tags) or ("READY" in tags)) and (("RECV" in tags)):
		i += 1
		continue

	if ("DIED" in tags) and (("RECV" in tags) or ("SEND" in tags)):
		i += 1
		continue

	if ("SEND_STARTED" in tags) and ("SEND" not in tags) and ("DIED" not in tags):
		i += 1
		continue

	if ("RECV_STARTED" in tags) and ("RECV" not in tags) and ("DIED" not in tags):
		i += 1
		continue

	if "READY" in tags:
		for outstate in outstates:
			print(k, statestr + "|" + outstate)
			k += 1
	else:
		print(k, statestr)
		k += 1

	i += 1

"""
Constraints:
	- STATUS/HEADER/BODY only when READY
"""