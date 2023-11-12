@echo off
setlocal
cls
color A
title    TCP Port Scanner V1.1 By WinEggDrop
echo            ======================================================
echo                       TCP Port Scanner V1.1 By WinEggDrop
echo                                   Good Luck!   
echo            ======================================================
set /p Port=Please enter the port you want to scan:
del ips.txt
del Result.txt
for /f "eol= tokens=1,2 delims= " %%i in (ip.txt) do s syn %%i %%j %Port% /save
for /f "eol=- tokens=1 delims= " %%i in (Result.txt) do echo %%i>>s1.txt
for /f "eol=P tokens=1 delims= " %%i in (s1.txt) do echo %%i>>s2.txt
for /f "eol=S tokens=1 delims= " %%i in (s2.txt) do echo %%i>>ips.txt
del s1.txt
del s2.txt
del Result.txt