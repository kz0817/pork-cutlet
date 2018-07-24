
PARSER = ./porkcutlet.py

all: michi.tun0.parsed ren.tun0.parsed

%.parsed: %.ptxt $(PARSER)
	$(PARSER) $< > $@

%.ptxt: %.dat
	tcpdump -n -r $< > $@

.PHONY: clean
clean:
	rm -f *.parsed *.ptxt
