#!/bin/sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

#IP1=`ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'`
IP1=`ifconfig interlink | grep 'inet' | cut -d: -f2 | awk '{print $2}'` # .3 = a | .4 = b
actualPassw=`cat /vpd/vpd1.txt | tail -n -1 | awk -F: '{print $5}'`
sysPassw="superuser"
adminPassw="admin"
actualOSPassw="ibmesscluster"
osPasswd="cluster"

actualIPmitoolIP=`ipmitool lan print 1 | grep -w "IP Address" | tail -n +2 | awk -F: '{print $2}'`

if [ -f /usr/lpp/mmfs/bin/tsplatformstat ]; then
    position=`/usr/lpp/mmfs/bin/tsplatformstat -C | tail -n +2 | cut -d: -f4`
else
    echo "Position can't be gathered"
fi 

if [ $IP1 == "169.254.1.3" ]; then
    if [ $position == "left" ]; then
        INTERLINK="169.254.1.1"
    else
        INTERLINK="169.254.1.2"
    fi
elif [ $IP1 == "169.254.1.4" ]; then
   if [ $position == "left" ]; then
        INTERLINK="169.254.1.1"
    else
        INTERLINK="169.254.1.2"
    fi
else
   echo "interlink IP could not determined. Ensure it is set and try again."
   exit 1
fi

echo "1. Will RESET BMC password"
echo "You will get asked for current BMC password"
echo "Possible current BMC password is: ${actualPassw}"
ssh -o ConnectTimeout=5 sysadmin@$INTERLINK "echo -e '$sysPassw\n$sysPassw' | passwd"
retVal=$?
if [ $retVal -ne 0 ]; then
    echo ""
    echo -e "${RED}[FAIL] There was a problem fixing sysadmin password${NC}"
else
    echo ""
    echo -e "${GREEN}[PASS] sysadmin password was succesfully changed to $sysPassw ${NC}"
fi

echo "2. Will RESET OS password"
echo -e "$osPasswd\n$osPasswd" | passwd
retVal=$?
if [ $retVal -ne 0 ]; then
    echo ""
    echo -e "${RED}[FAIL] There was a problem fixing OS password${NC}"
else
    echo ""
    echo -e "${GREEN}[PASS] OS password was succesfully changed to $osPasswd ${NC}"
fi

echo ""
echo "3. Will RESET admin password"
expect -c "
spawn ipmitool user set password 2
expect \"Password for user 2:\"
send \"${adminPassw}\r\"
expect \"Password for user 2:\"
send \"${adminPassw}\r\"
exit 0"
retVal=$?
if [ $retVal -ne 0 ]; then
    echo ""
    echo -e "${RED}[FAIL] There was a problem fixing admin (ipmitool) password ${NC}"
else
    echo ""
    echo -e "${GREEN}[PASS] admin (ipmitool) password was succesfully changed to $adminPassw ${NC}"
fi

echo ""
echo "4. Will RESET BMC VLAN tag"
/bin/ipmitool lan set 1 vlan id off
retVal=$?
if [ $retVal -ne 0 ]; then
    echo ""
    echo -e "${RED}[FAIL] There was a problem reseting BMC VLAN ID ${NC}"
else
    echo ""
    echo -e "${GREEN}[PASS] BMC VLAN ID was succesfully disabled ${NC}"
fi
