GoFlow2 – NetFlow / IPFIX / sFlow collector used by IT Ops "Network traffic" (2.10.0)

Put the GoFlow2 program in THIS folder:
  Windows: goflow2-2.2.7-windows-amd64.exe
  Linux:   goflow2 (or install it on the PATH)
Download: https://github.com/netsampler/goflow2/releases  (BSD-3-Clause licence, project netsampler/goflow2)

Check the file you downloaded (PowerShell):  Get-FileHash .\goflow2-2.2.7-windows-amd64.exe
  v2.2.7 windows-amd64  SHA-256 900D2BF50571B13921A0E2383406644C8C84FDC24AB24B5FCD743132E750A60E
  v2.2.7 linux-amd64    SHA-256 63D3BB6C4E458F56AE3268EAC74979DA1FEE0CEA5342362295E7D587784AF14B
(hashes of the files downloaded from the GitHub release page on 2026-11-13; GoFlow2 does not publish a checksum file)

IT Ops starts and stops GoFlow2 itself (Network traffic -> Settings -> Collect traffic). Do not run it by hand at the
same time – both would want UDP 2055. Another path: set FLOW_COLLECTOR=<full path to the program>.
