#!/usr/bin/sh
logWarn(){
        START='\033[01;33m'
        END='\033[00;00m'
        MESSAGE=${@:-""}
        echo "${START}${MESSAGE}${END}"
}

logInfo(){
        START='\033[01;32m'
        END='\033[00;00m'
        MESSAGE=${@:-""}
        echo "${START}${MESSAGE}${END}"
}

logError(){
        START='\033[01;31m'
        END='\033[00;00m'
        MESSAGE=${@:-""}
        echo "${START}${MESSAGE}${END}"
}

log(){
        MESSAGE=${@:-""}
        echo "${MESSAGE}"
}

#log "Mensaje con Texto Normal"
#logInfo "Mensaje con Texto Informativo (Verde)"
#logWarn "Mensaje con Texto para Alarma (Amarillo)"
#logError "Mensaje con Texto para Error (Rojo)"

usr="$USER"
pass="admin"

echo ""
logWarn "... Applying Update to ${usr} ..."
expect -c "
spawn /usr/local/bin/apt update -y
expect \"${usr}:\"
send \"${pass}\r\"
expect eof"

Val=$?
if [ $Val -ne 0 ]; then
	echo ""
	logWarn "... Fix broken install to ${usr} ..."
	expect -c"
	spawn /usr/local/bin/apt --fix-broken install
	expect \"${usr}:\"
	send \"${pass}\r\"
	expect eof"
else 
	
	echo ""
	logWarn "... Applying upgrade to ${usr} ..."
	expect -c "
	spawn /usr/local/bin/apt upgrade -y
	expect \"${usr}:\"
	send \"${pass}\r\"
	interact"
fi

Val=$?
if [ $Val -ne 0 ]; then
    echo ""
    logError "[FAIL] Fixing problem"
else
    echo ""
    logInfo "[PASS] The update and upgrade was succesful"
fi

