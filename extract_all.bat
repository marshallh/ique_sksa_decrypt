@echo off
@echo 
@echo Put all the sksa blobs in a folder called "sksa" whereever you run this.
@echo Also put ique_sksa_decrypt.exe in the same folder with this batch file.
@echo YOU MUST REPLACE THE KEY VALUES BELOW AND REMOVE THE 'REM' TO GET ANY RESULTS
@echo
rem ckey=Common key
rem skey=Secure Kernel key
rem siv=Secure Kernel IV

if not exist out mkdir out

for %%F in (sksa\*.*) do (
   ique_sksa_decrypt -f %%~pnxF -skout out\%%~nxF_sk.bin -sa1out out\%%~nxF_sa1.bin -sa2out out\%%~nxF_sa2.bin -ckey %ckey% -skey %skey% -siv %siv%
)
