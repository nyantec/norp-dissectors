pcap := \
	$(subst .eth,.pcap,$(sort $(wildcard *.eth))) \
	$(subst .wlan,.pcap,$(sort $(wildcard *.wlan))) \
	$(subst .ipv4,.pcap,$(sort $(wildcard *.ipv4))) \
	$(subst .ipv6,.pcap,$(sort $(wildcard *.ipv6)))

everything: $(pcap)

%.pcap: %.eth
	text2pcap -l 1 $< $@

%.pcap: %.wlan
	text2pcap -l 105 $< $@

%.pcap: %.ipv4
	text2pcap -l 228 $< $@

%.pcap: %.ipv6
	text2pcap -l 229 $< $@

.PHONY: everything
