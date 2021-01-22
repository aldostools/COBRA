@echo off
cls

set PS3SDK=/c/PSDK3v2
set WIN_PS3SDK=C:/PSDK3v2
set PS3DEV=%PS3SDK%/ps3dev2
set PATH=%WIN_PS3SDK%/mingw/msys/1.0/bin;%WIN_PS3SDK%/mingw/bin;%PS3DEV%/ppu/bin;
set CYGWIN=nodosfilewarning

if exist stage2.bin_* del /q stage2.bin_*>nul
if exist stage2.cex   del /q stage2.cex>nul
if exist stage2.dex   del /q stage2.dex>nul

cd stage2
make clean
make all
make clean
pause
