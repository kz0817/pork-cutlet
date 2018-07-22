michi.tun0.parsed:

%.parsed: %.ptxt pktparse.py
	./pktparse.py $< > $@

%.ptxt: %.dat
	tcpdump -n -r $< > $@
