md %2

copy /y %1\passthru.sys %2\
copy *.inf %2\

signtool sign /v /ac c:\certs\MSCV-VSClass3.cer /s my /n "Stanford University" /t http://timestamp.verisign.com/scripts/timestamp.dll %2\passthru.sys

inf2cat /driver:%2 /os:XP_X64,Vista_X64,7_X64,Server2003_X64,Server2003_IA64,Server2008_X64,Server2008_IA64,Server2008R2_X64,Server2008R2_IA64,XP_X86,Vista_X86,7_X86,Server2003_X86,Server2008_X86

signtool sign /v /ac c:\certs\MSCV-VSClass3.cer /s my /n "Stanford University" /t http://timestamp.verisign.com/scripts/timestamp.dll %2/netsf.cat %2/netsf_m.cat
