# Node_slowness_script
This is a master script which can be use to analyse the RHCOS node slowness issue. 

Usage:
  check-node-slowness.sh /path/to/extracted-sosreport
  check-node-slowness.sh /path/to/sosreport.tar.xz
  check-node-slowness.sh --live

Reads an sos-report (or the local system with --live) and reports what is
slow: CPU, iowait, steal, memory, PSI, D-state tasks, disk latency, full
filesystems, multipath/iSCSI, and a few log patterns.
