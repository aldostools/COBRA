@echo off
cls
set PS3SDK=/c/PSDK3v2
set PS3DEV=/c/PSDK3v2/ps3dev2
set WIN_PS3SDK=C:/PSDK3v2
set SCETOOL=C:\PSDK3v2\MinGW\msys\1.0\bin
set PATH=%WIN_PS3SDK%/mingw/msys/1.0/bin;%WIN_PS3SDK%/mingw/bin;%PS3DEV%/ppu/bin;%SCETOOL%;
set CYGWIN=nodosfilewarning

if not exist ..\BIN mkdir ..\BIN

cd lv2gen
rm -f *.o *.exe
make -f Makefile all
cd ../nocfw_kern_plugin/payload
make -f Makefile all
cd ../../stage0_file
rm -f *.o *.elf *.self *.bin *.map ../lv1/src/*.o ../debug/src/*.o ../lv2/src/*.o
make -f Makefile all
pause
