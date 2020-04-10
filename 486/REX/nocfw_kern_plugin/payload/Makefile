
clean:
	rm -f *.o *.elf *.self *.48* *.bin *.map ../lv1/src/*.o ../debug/src/*.o ../lv2/src/*.o

all:
	rm -f *.o *.elf *.self *.48* *.bin *.map ../lv1/src/*.o ../debug/src/*.o ../lv2/src/*.o
	make -f Makefile_CEX --no-print-directory

	rm -f *.o *.elf *.self *.48* *.map ../lv1/src/*.o ../debug/src/*.o ../lv2/src/*.o
	make -f Makefile_DEX --no-print-directory
	rm -f *.o *.elf *.48* *.map ../lv1/src/*.o ../debug/src/*.o ../lv2/src/*.o
	rm -f *.o *.elf *.self ../lv1/src/*.o ../debug/src/*.o ../lv2/src/*.o
