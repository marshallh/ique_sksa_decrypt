@echo off
@echo 
@echo Put all the sksa blobs in a folder called "sksa" whereever you run this.
@echo Also put the built exe in the same folder with this batch file.
@echo YOU MUST REPLACE THE KEY VALUES BELOW TO GET ANY RESULTS
@echo
rem ckey = Common key
rem skey = Secret Kernel key
rem siv  = Secret Kernel IV

for %%F in (sksa\*.*) do (
   ique_sksa_decrypt -f %%~pnxF -skout %%~nxF_sk.bin -sa1out %%~nxF_sa1.bin -sa2out %%~nxF_sa2.bin -ckey 0 -skey 0 -siv 0
)
