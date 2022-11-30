#!/bin/bash

#IP1=`ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'`
IP1=`ifconfig interlink | grep 'inet' | cut -d: -f2 | awk '{print $2}'`
passw=`cat /vpd/vpd1.txt | tail -n -1 | awk -F: '{print $5}'`

if [ $IP1 == "169.254.1.3" ]; then
   INTERLINK="169.254.1.1"
elif [ $IP1 == "169.254.1.4" ]; then
   INTERLINK="169.254.1.2"
else
   echo "interlink IP could not determined. Ensure it is set and try again."
   exit 1
fi

if [ $passw == "" ]; then
    echo "VPD is not available on node, please check /vpd/vpd1.txt file exists."
    exit 2
fi 

echo "1. Will change BMC password"
echo "You will get asked for current BMC password"
ssh -o ConnectTimeout=5 sysadmin@$INTERLINK "echo -e '$passw\n$passw' | passwd"
retVal=$?
if [ $retVal -ne 0 ]; then
    echo "[FAIL] There was a problem fixing sysadmin password"
else
    echo "[PASS] sysadmin password was succesfully changed to $passw"
fi

echo ""
echo "2. Will change admin password"
expect -c "
spawn ipmitool user set password 2
expect \"Password for user 2:\"
send \"${passw}\r\"
expect \"Password for user 2:\"
send \"${passw}\r\"
exit 0"
retVal=$?
if [ $retVal -ne 0 ]; then
    echo ""
    echo "[FAIL] There was a problem fixing admin (ipmitool) password"
else
    echo ""
    echo "[PASS] admin (ipmitool) password was succesfully changed to $passw"
fi
