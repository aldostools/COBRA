PAYLOADS = 4_87 4_87DEX

clean:
	@rm -f *~ *.*~ *.o *.elf *.4_* *.cex *.dex *.release *.debug *.map *.lzma ../lv2/src/*.o ../lv1/src/*.o ../debug/src/*.o

all: $(PAYLOADS)

export COBRA_VER

$(PAYLOADS):
	$(eval COBRA_VER = $@)
	@rm -f *.o *.elf *.bin *.release *.debug *.cex *.dex *.map *.lzma ../lv2/src/*.o ../lv1/src/*.o ../debug/src/*.o
	make -f Makepayload --no-print-directory
