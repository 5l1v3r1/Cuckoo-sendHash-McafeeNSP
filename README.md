# Cuckoo-sendHash-McafeeNSP
a script continously active, monitoring (through monitoring functionality is available from the Linux kernel ) Cuckoo sandbox analysis reports,
once a new report is generated, script fetches the estimate score of the malware sample and sends the HASH value of the file to the Mcafee NSP to be blocked in the network


#Running steps:
1- open the script and add the Mcafee mgmt IP in front of the value "MCFE_MGMT"
2- run the script
3- open Cuckoo GUI and test a file sample
