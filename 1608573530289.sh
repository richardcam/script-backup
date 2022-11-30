#!/bin/bash
################################################
# IBM OC Fedora Build Script for IBM           #
# 2020 IBM Albany Research                     #
# Written by: Clint Oteri and Matthew Lavigne  #
# Email: oteri@us.ibm.com                      #
# Email: matthew.lavigne1@ibm.com              #
################################################

export LC_ALL=en_US.utf8
export LANG=en_US.utf8 

ERROR=false
GRUB=false
DRACUT=false
REBOOT=false
PREV_UPDATE="				  Already Updated."
IP=""
username=""
RPMLIST=""
GROUPSLIST=""
OUTPUT=""
w3user=""
w3pass=""
VPN_PID=""

GEOGRAPHY=""
JOBROLE=""
OWNER=""
SecType=""
SecType2=""
MachineType=""
PhysicalDevice=""
OpsysName=""
CebImageName=""
WorkstationUse=""
WorkstationUseAbbrev=""
username=""
password=""
root_password=""
BESPATH="/var/opt/BESClient/__BESData/__Global/Logs"
FEDORA_VERSION=""
EFI=""
ALREADY_CONNECTED="false"
NVIDIA_KMOD_TYPE=""
DO_GOOGLE="false"
DO_NVIDIA="false"
DNF_OPTIONS=""
TMP_OPTIONS=""
_HOME=""
_DESKTOP=""
_DOWNLOADS=""
_DOCUMENTS=""

function ibm_w3_vpn {
	echo "##################################################"
	echo ""
	echo "Connecting to the IBM GettingStarted VPN with your W3 Userid"
	echo ""
	rc=$(ping -c 1 ocfedora.hursley.ibm.com 2>&1 >/dev/null)
	if [ ! $? -eq 0 ]; then
		rm -f /tmp/ibm_w3_vpn.txt
		echo "${w3pass}" | openconnect --passwd-on-stdin --protocol=anyconnect --user=${w3user} sasvpn03.pok.ibm.com/gettingstarted | tee /tmp/ibm_w3_vpn.txt &
		sleep 2
		echo ""
		status 'sleep 10' 'Waiting on VPN'
		VPN_PID=$(ps -ef | grep openconnect | grep -v grep | awk '{print $2}')
		echo ""
		rc=$(grep "^Connected as" /tmp/ibm_w3_vpn.txt) 
		if [ $? -eq 0 ]; then
			echo ""
			echo "Note: You are using an IBM VPN connection with restrictions and limited"
			echo "access to IBM. This is for inital setup and registraton purposes only."
			echo ""
			echo "*** IBM W3 VPN Connected ***"
		else
			echo "Error: IBM W3 VPN Not Connected - Please check your password"
			exit 1
		fi
		if [[ ${FEDORA_VERSION} -ge 33 ]]; then
			resolvectl dns tun0 9.0.130.50 9.0.128.50
			resolvectl domain tun0 ibm.com
		fi
		echo "VPN PID=${VPN_PID}"
		echo "					  Success."
	else
		echo "Already Connected to IBM - W3 Getting Started VPN is not needed."
		ALREADY_CONNECTED="true"
	fi
	echo "##################################################"
	echo ""
	read -p "Press Enter to Continue " press
	echo ""
}

# ask to kill the vpn.. this was useful for testing..but we decided on killing the
# vpn at script end
#function kill_ibm_w3_vpn {
#	if [ ! "${VPN_PID}" == "" ]; then 
#		echo "##################################################"
#		echo ""
#		echo "You can disconnect if you had a successful VPN Registration."
#		read -p "Leave w3 GettingStarted VPN Connection Active? [Y/N]: " killvpn
#		echo ""
#		rc=$(echo "${killvpn}"| grep -i "^n")
#		if [ $? -eq 0 ]; then
#			echo "Closing VPN Connection"
#			kill ${VPN_PID} 2>&1 >/dev/null
#		else
#			echo "Leaving VPN Connection Active"
#		fi
#	fi
#}

function kill_ibm_w3_vpn {
	if [ ! "${VPN_PID}" == "" ]; then 
		echo "##################################################"
		echo ""
		echo "Closing w3 GettingStarted VPN Connection"
		kill ${VPN_PID} 2>&1 >/dev/null
	fi
}

function wait_for_registration {
	echo "##################################################"
	echo "Waiting to Upload Registration for IBM SAS VPN"
	echo ""
	BESLOG=$(ls -1htr ${BESPATH}|tail -1)
	if [ "${BESLOG}" == "" ]; then
		echo "BESClient Log does not exist - Did the OCFedora Base Layer install?"
		exit 1
	fi
	echo "" >/tmp/besout.txt
	tail -f ${BESPATH}/${BESLOG} | grep -m 1 'Registered with url' > /tmp/besout.txt &
	TAIL_PID=$!
	count=1
	while true; do
		grep -q "Registered with url" /tmp/besout.txt
		if [ $? -eq 0 ];then
			echo ""
			echo ""
			echo ""
			echo "################################################################"
			echo "#                                                              #"
			echo "# Successfully Registered with TEM Endpoint for IBM SAS VPN!!! #"
			echo "#                                                              #"
			echo "################################################################"
			echo ""
			echo "It can take 45 Minutes to an hour for the Certificate to show up."
			echo ""
			rc=$(kill ${TAIL_PID} 2>&1 >/dev/null)
			rm -f /tmp/besout.txt
			date > /root/.vpn-registered
			echo ""
			read -p "Press Enter to continue" inputs
			if [[ "${ALREADY_CONNECTED}" == "false" ]]; then
				kill_ibm_w3_vpn
				sleep 3
				status "sleep 5" "Waiting for VPN to close"
			fi
			get_vpn
			break
		elif [ ${count} -eq 15 ]; then
			echo "Error: It's been an hour and we still do not have Registration"
			echo "Try again later."
			rc=$(kill ${TAIL_PID} 2>&1 >/dev/null)
			rm -f /tmp/besout.txt
			break
		else
			status "systemctl restart besclient" "Restarting BESClient Service"
			# Check to see if the Log rolled at midnight.. If so, start tailing the new log
			NEWLOG=$(ls -1htr ${BESPATH}|tail -1)
			if [ ! "${NEWLOG}" == "${BESLOG}" ]; then
				echo "Informational: BESClient Log Rolls at Midnight."
				rc=$(kill ${TAIL_PID} 2>&1 >/dev/null)
				tail -f ${BESPATH}/${NEWLOG} | grep -m 1 'Registered with url' >> /tmp/besout.txt &
				TAIL_PID=$!
			fi
			echo ""
			if [ ${count} -eq 1 ]; then
				status "sleep 30" "VPN Registration Attempt #${count} : Sleeping 30 Seconds"
			elif [ ${count} -lt 3 ]; then
				status "sleep 60" "VPN Registration Attempt #${count} : Sleeping 1 Minute"
			elif [ ${count} -lt 5 ]; then
				status "sleep 120" "VPN Registration Attempt #${count} : Sleeping 2 Minutes"
			elif [ ${count} -lt 10 ]; then
				status "sleep 180" "VPN Registration Attempt #${count} : Sleeping 3 Minutes"
			elif [ ${count} -lt 15 ];then 
				status "sleep 300" "VPN Registration Attempt #${count} : Sleeping 5 Minutes"
			else
				status "sleep 900" "VPN Registration Attempt #${count} : Sleeping 15 Minutes"
			fi
			let count=${count}+1
		fi
	done
}
 
# Create a spinning icon so the user has something to look at while we
# are doing important work in the background.
# if timeout is specfied, stop at the timeout
function spin {
	comment="${1}"
	while true ; do 
		for spinner in  \-  \\  \|  \/  \-  \\  \|  \/ ; do 
			if [ -f /tmp/stopper ]; then
				break 3
			fi
			echo -n -e "\r${comment}:  ${spinner}     "
			sleep 0.1
		done  
	done
}

# Print status to user during any long running process. 
# results are in returned in $OUTPUT
# you could run status '<command>' '<description>' for anything.
function status {
	comment="${2}"
	rm -f /tmp/stopper
	spin "${comment}" & >/dev/null
	OUTPUT=$(eval "$1")
	touch /tmp/stopper
	echo -e "\r${comment}:  Done    "
	sleep 1
}

# Format RPMS without their versioning info.
# call it with status so the user doesnt think the script is hanging.
function get_rpm_list {
	status 'rpm -qa|sort|sed "s/-[0-9].*//g"|sed "s/^/\"/g"|sed "s/$/\"/g"' 'Compiling List of Installed RPMS'
	RPMLIST="${OUTPUT}"
}

function get_groups_list {
	if [[ "${ALREADY_CONNECTED}" == "false" ]]; then
		rc=$(dnf repolist enabled| grep -w openclient|grep -v openclient-gsa)
		if [[ "${rc}" == "" ]]; then
			status 'dnf -y groups list installed|grep -A32767 "Installed Groups:"|grep -v "Installed Groups:"|sed "s/^ *//g"|sed "s/^/\"/g"|sed "s/$/\"/g"' 'Compiling List of Installed Groups'
		else
			status 'dnf -y --disablerepo=openclient groups list installed|grep -A32767 "Installed Groups:"|grep -v "Installed Groups:"|sed "s/^ *//g"|sed "s/^/\"/g"|sed "s/$/\"/g"' 'Compiling List of Installed Groups'
		fi
	else
		status 'dnf -y groups list installed|grep -A32767 "Installed Groups:"|grep -v "Installed Groups:"|sed "s/^ *//g"|sed "s/^/\"/g"|sed "s/$/\"/g"' 'Compiling List of Installed Groups'
	fi
	GROUPSLIST="${OUTPUT}"
}


# Basic check to see if we already have a package installed.
# 1 = Already installed
# 0 = We dont have it
function rpm_checker {
	input="${1}"
	validate=$(echo "${RPMLIST}" | grep "\"${input}\"")
	return $((1-$?))
}

# Basic check to see if we already have a specific group installed
# 1 = Already installed
# 0 = We dont have it
function group_checker {
	input="${1}"
	validate=$(echo "${GROUPSLIST}" | grep "\"${input}\"")
	return $((1-$?))
}

# selectivly check for and install group
function install_group {
	group="${1}"
	group_checker "${group}" 
	if [ $? -eq 0 ]; then
		dnf -y ${DNF_OPTIONS} groupinstall "${group}"
		check $?
	else
		echo "Already Installed -                      Skipping."
	fi
}

# selectivly check for and install items that are not already installed
function install_list {
	list="${1}"
	comment="${2}"
	applist=""
	for package in $(echo ${list});do 
		rpm_checker ${package} && applist=$(echo $applist $package)
	done
	if [ ! "${applist}" == "" ]; then
		dnf -y ${DNF_OPTIONS} install ${applist}
		check $?
	else
		echo "${comment}"
	fi
}

# selectivly check for and uninstall items
function remove_list {
	list="${1}"
	comment="${2}"
	applist=""
	for package in $(echo ${list});do 
		rpm_checker ${package} || applist=$(echo $applist $package)
	done
	if [ ! "${applist}" == "" ]; then
		dnf -y ${DNF_OPTIONS} remove ${applist}
		check $?
	else
		echo "${comment}"
	fi
}
# Are we root?
function root_check {
	root=$(whoami)
	if [ ! "${root}" == "root" ]; then
		echo ""
		echo "You must run this script as root"
		echo "ie: sudo ${0}"
		echo ""
		exit 1
	fi
}

# Basic Check function, gives the user a chance to kill it to investigate
function check {
	rc=${1}
	if [ ${rc} -eq 0 ]; then
		echo "					  Success."
	else
		echo "					  Failed."
		ERROR=true
		echo ""
		echo "Hit Ctrl-c to exit, or Press Enter to Continue running"
		read line
	fi
}
# Function to validate a typed in password with the system password
# based on the crypto algorithm and salt stored in /etc/shadow
# Compare resultant Hashes and validate
function check_account {
	local account_type="${1}"
	local prompt_str="${2}"
	local user_name=""
	local pass_word=""
	local UID_BASE=1000
	while true ; do
		ALG=""
		echo ""
		if [ "${account_type}" == "ROOT" ]; then
			user_name=root
			read -s -p "${prompt_str}" pass_word
		else
			default_user=$(getent passwd $UID_BASE | cut -d':' -f 1)
			if [[ ! $? -eq 0 ]]; then
				default_user="NoneFound"
			fi
			read -p "${prompt_str} [ ${default_user} ]: " user_name
			if [[ "${user_name}" == "" ]]; then
				user_name="${default_user}"
			fi
			user_ent=$(getent shadow "${user_name}")
			if [ ! $? == 0 ]; then
				echo "User ${user_name} does not exist, please try again"
				continue
			fi
			read -s -p "Password: " pass_word
		fi
		# Parse /etc/shadow for a specific user and get the resultant password
		
		if [[ ! "$(getent shadow "${user_name}" | cut -d':' -f 2)" == "!" ]]; then
			read Algorithm Salt Hash  <<< $(getent shadow "${user_name}" | cut -d':' -f 2 | awk -F'$' '{print $2" "$3" "$4"\n"}')
			case "${Algorithm}" in
				"1")
					ALG="md5"
					;;
				"5")
					ALG="sha-256"
					;;
				"6")
					ALG="sha-512"
					;;
				*)
					echo "Error: Check to make sure the user was built properly."
					exit 1
					;;
			esac
			# build a password based off what the user typed in and compare it to the password in /etc/shadow
			read typed_Algorithm typed_Salt typed_Hash <<< $(mkpasswd -m "${ALG}" "${pass_word}" "${Salt}" | awk -F'$' '{print $2" "$3" "$4"\n"}')
			if [ "${typed_Hash}" == "${Hash}" ]; then
				echo ""
				echo ""
				echo "Password for ${user_name} is Valid..."
				break
			else
				echo ""
				echo ""
				echo "Password for ${user_name} is not Valid...Please try again."
			fi
		else 	
			if [ "${account_type}" == "ROOT" ]; then
				echo ""
				echo "Password for root has not been set up yet."
				echo ""
				read -p "Do you want to set root to the same password as you are using for ACCOUNT: ${username}? [Y/N] " validate
				rc=$(echo "${validate}"| grep -qi "^y")
				if [ $? -eq 0 ]; then 
					echo ""
					echo "Note: This password change will occur after the OC Base Layer is installed."
					break
				else
					while true; do
						echo ""
						echo "Set a new root password."
						passwd root
						if [ $? -eq 0 ]; then

							check_account ROOT "Type your root password in again to Validate: "
							break 2
						fi
					done
				fi
			else
				echo "Error: Check to make sure the user ${user_name} was built properly."
				exit 1
			fi
		fi
	done
	# Success. Set the vars we need.
	if [ "${account_type}" == "ROOT" ]; then
		root_password="${pass_word}"
	else
		username="${user_name}"
		password="${pass_word}"
		_HOME=$(su - ${username} -c 'xdg-user-dir')
		_DESKTOP=$(su - ${username} -c 'xdg-user-dir DESKTOP')
		_DOWNLOADS=$(su - ${username} -c 'xdg-user-dir DOWNLOAD')
		_DOCUMENTS=$(su - ${username} -c 'xdg-user-dir DOCUMENTS')
	fi
}

function intro {
	FEDORA_VERSION=$(uname -r | grep -o "fc.*" | sed "s/.$(uname -m)//g" | sed 's/fc//g')
	echo "   _______  __  ___  ____  _____  ____       __             "
	echo "  /  _/ _ )/  |/  / / __ \/ ___/ / __/__ ___/ /__  _______ _"
	echo " _/ // _  / /|_/ / / /_/ / /__  / _// -_) _  / _ \/ __/ _ \`/"
	echo "/___/____/_/  /_/  \____/\___/ /_/  \__/\_,_/\___/_/  \_,_/"
	echo ""
	echo "##################################################"
	echo "# IBM OpenClient Fedora ${FEDORA_VERSION} Installation Script   #"
	echo "##################################################"
	echo ""
	echo "Join us on Slack #ocfedora"
	echo ""
}

function initialize {
	# are we Fedora?
	if [[ ! -f /etc/fedora-release ]]; then
		echo "This installation script is only supported on Fedora Releases"
		exit 1
	fi

	# is the root fs encrypted? Test to see if we are VM?
	btrfs_uuid=$(grep -w btrfs /etc/fstab | grep -w / | awk '{print $1}' | cut -d'=' -f 2)
	if [[ "${btrfs_uuid}" == "" ]]; then
		if [[ "$(lsblk | grep / -w -B1 | grep luks)" == "" ]]; then
			echo "Error: Root Filesystem is not luks encrypted, this build is not suitable for open client installation."
			exit 1
		fi
	else
		luks=$(sfdisk -g | grep luks | cut -d':' -f 1)
		if [[ ! "${luks}" == "" ]]; then
			for parts in "${luks}"; do
				blk_id=$(echo "${blk_id} $(blkid ${parts})")
			done
		fi
		echo "${blk_id}" | grep -q "${btrfs_uuid}"
		if [[ ! $? -eq 0 ]]; then
			echo "Error: Root Filesystem is not luks encrypted, this build is not suitable for open client installation."
			exit 1
		fi
	fi

	# are we 64 bit?
	if [[ ! "$(uname -m)" == "x86_64" ]]; then
		echo "Error: This installation script only supports 64 Bit systems."
		exit 1
	fi
	# are we running under either X or Wayland? Required for IBM Registration tool
	rc=$(xwininfo -root 2>&1 >/dev/null)
	if [ ! $? -eq 0	]; then
		echo "Error: This script needs to be run in graphical mode under X or Wayland"
		echo "If you are running in Graphical mode, then reboot, or log out and log back in as"
		echo "your X/Wayland session is in a funky state."
		echo ""
		echo "or you can try to run \"xhost +SI:localuser:root\" as your user."
		echo ""
		echo "Then rerun this script to continue."
		exit 1
	fi
	# are we on any network?
	# HAHA lets check Microsoft's own Network Connectivity Status Indicator (NCSI)
	rc=$(ping -c 1 www.msftncsi.com 2>&1 >/dev/null)
	if [[ ! $? -eq 0 ]]; then
		# If that Fails, then lets check google's primary DNS server.
		rc=$(ping -c 1 8.8.8.8 2>&1 >/dev/null)
		if [[ ! $? -eq 0 ]]; then
			echo "You need a network connection for this process."
			exit 1
		fi
	fi

	check_account USER "Fedora Laptop/Workstation Username"
	echo "##################################################"
	check_account ROOT "Password for root: "
	echo "##################################################"
	echo ""
	echo "Note: you may need to update your passwords again after"
	echo "the IBM Security Rules are set."
	echo "##################################################"
	echo "" 
	read -p "Please enter your W3 Userid: " w3user
	read -s -p "Password: " w3pass
	echo ""
	echo ""
	hostname_change
	echo ""
	bios_check
}

function bios_check {
	rc=$(ls /sys/firmware/efi 2>&1 >/dev/null)
	if [ $? -eq 0 ]; then
		echo "EFI system detected...ensure you have CSM support turned on in the BIOS->Boot Options!"
	else
		echo "Legacy BIOS system detected..."
	fi
}

function hostname_change {
	echo "##################################################"
	host_name=$(hostname)
	echo "Your current hostname is set to ${host_name}"
	read -p "Would you like to change it? [Y/N]: " yesno
	echo ""
	rc=$(echo "${yesno}"| grep -i "^y")
	if [ $? -eq 0 ]; then
		while true;do 
			read -p "Please type in a new hostname: " new_host
			hostnamectl set-hostname "${new_host}"
			host_name=$(hostname)
			echo "Your new hostname is now ${host_name}"
			read -p "Is this correct? [Y/N]: " yesno
			rc=$(echo "${yesno}"| grep -i "^y")
			if [ $? -eq 0 ]; then
				break
			fi
			done
	fi
}
function disable_openclient {
	TMP_OPTIONS="${DNF_OPTIONS}"
	if [[ "${ALREADY_CONNECTED}" == "false" ]]; then
		# We are using the W3 Getting Started VPN - We will use the GSA Repo
		# so we will temporarily disable the openclient repo if we find it active
		rc=$(dnf repolist enabled| grep -w openclient|grep -v openclient-gsa)
		if [[ ! "${rc}" == "" ]]; then
			DNF_OPTIONS="${TMP_OPTIONS} --disablerepo=openclient"
		fi
	fi
}

function dnf_upgrade {
	echo ""
	echo "##################################################"
	echo ""
	echo "Ensuring the system is up to date."
	echo ""
	echo "Running    # dnf upgrade --refresh"
	echo ""
	echo "Note: This will reboot the system if necessary"
	echo ""
	echo "Re-Run this script after rebooting to restart the Installation process."
	echo ""
	echo "Press Enter to continue, or Ctrl-c to quit."
	read line
	cat /dev/null > /tmp/dnf-upgrade.txt
	disable_openclient
	dnf -y ${DNF_OPTIONS} upgrade --refresh | tee -a /tmp/dnf-upgrade.txt
	grep -i "^ kernel\|^ pam\|^ glib\|^ nvidia\|^ akmod\|^ virtual\|^ libvirt\|^ qemu\|^ systemd\|^ crypt\|^ dbus\|^ dracut\|^ grub\|^ elf\|^ kmod" /tmp/dnf-upgrade.txt 2>&1
	if [ $? -eq 0 ];then
		echo ""
		echo "System Packages Upgraded - Reboot Required."
		echo ""
		echo "Re-Run this script after rebooting to continue where we left off."
		echo ""
		echo "Press Enter to reboot or Ctrl-c to Cancel"
		read line
		reboot
	fi

	echo "##################################################"
	echo ""
	echo "dnf upgrade complete, System is up to date."
	echo ""
}

function vimrc_root {
	echo "##################################################"
	echo "Set a few .vimrc defaults for root"
	rc=$(grep -q "^colorscheme" /root/.vimrc 2>&1 >/dev/null)
	if [ ! $? == 0 ]; then
		echo -e "colorscheme default\nsyntax on" >> /root/.vimrc
		rc=$(grep -q "^colorscheme" /root/.vimrc 2>&1 >/dev/null)
		check $?
	else
		echo "${PREV_UPDATE}"
	fi
}

function vimrc_user {
	echo "##################################################"
	echo "Set a few .vimrc defaults for ${username}"
	rc=$(grep -q "^colorscheme" ${_HOME}/.vimrc 2>&1 >/dev/null)
	if [ ! $? == 0 ]; then
		echo -e "colorscheme default\nsyntax on" >> ${_HOME}/.vimrc
		rc=$(grep -q "^colorscheme" ${_HOME}/.vimrc 2>&1 >/dev/null)
		check $?
	else
		echo "${PREV_UPDATE}"
	fi
}

function ipv4_forwarding {
	echo "##################################################"
	echo "Enable IPV4 Forwarding for KVM"
	rc=$(grep -q "^net.ipv4.ip_forward = 1$" /etc/sysctl.d/90-ipv4_forwarding.conf 2>&1 >/dev/null)
	if [ ! $? == 0 ]; then
		echo -e "# Enable IPV4 Forwarding\nnet.ipv4.ip_forward = 1" >> /etc/sysctl.d/90-ipv4_forwarding.conf
		rc=$(grep -q "^net.ipv4.ip_forward = 1$" /etc/sysctl.d/90-ipv4_forwarding.conf 2>&1 >/dev/null)
		check $?
		
		rc=$(sysctl -p)
	else
		echo "${PREV_UPDATE}"
	fi
}

function disable_selinux {
	echo "##################################################"
	echo "Disabling SELinux"
	setenforce 0
	grep -q "^SELINUX=disabled$" /etc/selinux/config
	if [ ! $? == 0 ]; then
		perl -pi -e 's/^SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
		perl -pi -e 's/^SELINUX=permissive/SELINUX=disabled/g' /etc/selinux/config
		grep -q "^SELINUX=disabled$" /etc/selinux/config
		check $?
	else
		echo "${PREV_UPDATE}"
	fi
}

function permissive_selinux {
	echo "##################################################"
	echo "Setting SELinux to Permissive"
	setenforce 0
	grep -q "^SELINUX=permissive$" /etc/selinux/config
	if [ ! $? == 0 ]; then
		perl -pi -e 's/^SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config
		perl -pi -e 's/^SELINUX=disabled/SELINUX=permissive/g' /etc/selinux/config
		grep -q "^SELINUX=permissive$" /etc/selinux/config
		check $?
	else
		echo "${PREV_UPDATE}"
	fi
}

function enable_discards_lvm {
	echo "##################################################"
	echo "Enable Discard passthrough for LVM (Dracut/initramfs)"
	grep -q "issue_discards = 1$" /etc/lvm/lvm.conf
	if [ ! $? == 0 ]; then
		perl -pi -e 's/issue_discards = 0/issue_discards = 1/g' /etc/lvm/lvm.conf
		grep -q "issue_discards = 1$" /etc/lvm/lvm.conf
		rc=$?
		check ${rc}
		if [ ${rc} -eq 0 ]; then
			# Tell the script to update initramfs
			DRACUT=true
		fi
	else
		echo "${PREV_UPDATE}"
	fi
}

function ssd_tweaks_fstab {
	echo "##################################################"
	echo "Enable Automatic Discard and SSD Tweaks in fstab"
	grep -q xfs /etc/fstab
	if [ $? -eq 0 ]; then
		echo "XFS Filesystems found"
		grep -q "xfs defaults,noatime,nodiratime,discard" /etc/fstab
		if [ ! $? == 0 ]; then
			perl -pi -e 's/xfs *defaults/xfs defaults,noatime,nodiratime,discard/g' /etc/fstab
			grep "xfs defaults,noatime,nodiratime,discard" /etc/fstab
			check $?
		else
			echo "${PREV_UPDATE}"
		fi
	fi

	grep -q ext4 /etc/fstab
	if [ $? -eq 0 ]; then
		echo "ext4 Filesystems found"
		grep -q "ext4 defaults,noatime,nodiratime,discard" /etc/fstab
		if [ ! $? == 0 ]; then
			perl -pi -e 's/ext4 *defaults/ext4 defaults,noatime,nodiratime,discard/g' /etc/fstab
			grep "ext4 defaults,noatime,nodiratime,discard" /etc/fstab
			check $?
		else
			echo "${PREV_UPDATE}"
		fi
	fi
}

function ssd_elevator_grub {
	echo "##################################################"
	echo "SSD Elevator Tweaks (GRUB)"
	grep -q "elevator=deadline" /etc/default/grub
	if [ ! $? == 0 ]; then
		perl -pi -e 's/rhgb quiet/elevator=deadline rhgb quiet/g' /etc/default/grub
		rc=$?
		check ${rc}
		if [ ${rc} -eq 0 ]; then
			# Tell the script to update GRUB
			GRUB=true
		fi
	else
		echo "${PREV_UPDATE}"
	fi
}
function ipv6_disable_grub {
	echo "##################################################"
	echo "Disable IPV6 SystemWide (GRUB)"
	grep -q "ipv6.disable=1" /etc/default/grub
	if [ ! $? == 0 ]; then
		perl -pi -e 's/rhgb quiet/ipv6.disable=1 rhgb quiet/g' /etc/default/grub
		rc=$?
		check ${rc}
		if [ ${rc} -eq 0 ]; then
			# Tell the script to update GRUB
			GRUB=true
		fi
	else
		echo "${PREV_UPDATE}"
	fi
}

function dnf_fastest_mirror {
	echo "##################################################"
	echo "Enabling Fastest Mirror option for DNF"
	grep -q "^fastestmirror=true$" /etc/dnf/dnf.conf
	if [ ! $? == 0 ]; then
		echo "fastestmirror=true" >> /etc/dnf/dnf.conf
		check $?
	else
		echo "${PREV_UPDATE}"
	fi
}

function update_dracut_grub {
	# check to see if we are EFI or Legacy BIOS
	rc=$(ls /sys/firmware/efi 2>&1 >/dev/null)
	if [ $? -eq 0 ]; then
		EFI=true
	else
		EFI=false
	fi
	# For lvm.conf and grub defaults updates
	if [ "${DRACUT}" == "true" ]; then
		echo "##################################################"
		echo "Checking if we have to run Dracut and Grub"
		echo "Yes - Running Dracut to refresh initrd"
		rc=1
		dracut -fv -I /etc/crypttab 2>&1 | grep -q "ERROR\|FAILED" || rc=0
		if [ ${rc} -eq 0 ]; then
			rc=$(find /boot -maxdepth 1 -type f -name 'initramfs-*.img' -mmin -1)
			echo "${rc}" | grep initramfs
			if [ $? -eq 0 ]; then
				echo "                                          Success."
				echo "##################################################"
				echo "Re-installing bootloader to pick up grub defaults"
				echo ""
				if [ "${EFI}" == "true" ]; then
					grub2-mkconfig -o /boot/efi/EFI/fedora/grub.cfg
					rc=$(find /boot/efi/EFI/fedora/grub.cfg -mmin -1)
				else
					grub2-mkconfig -o /boot/grub2/grub.cfg
					rc=$(find /boot/grub2/grub.cfg -mmin -1)
				fi
				echo "${rc}" | grep grub.cfg
				check $?
				echo "##################################################"
			else
				echo "					Failed"
				echo "Dracut Failed - Not installing GRUB"
			fi
		else
			echo "					Failed"
			echo "Dracut Failed - Not installing GRUB"
			ERROR=true
			rc=1
			check ${rc}
		fi
	else
		# Check to see if we still need to Update GRUB
		if [ "${GRUB}" == "true" ]; then
			echo "##################################################"
			echo "Re-installing bootloader to pick up grub defaults"
			echo ""
			if [ "${EFI}" == "true" ]; then
				grub2-mkconfig -o /boot/efi/EFI/fedora/grub.cfg
				rc=$(find /boot/efi/EFI/fedora/grub.cfg -mmin -1)
			else
				grub2-mkconfig -o /boot/grub2/grub.cfg
				rc=$(find /boot/grub2/grub.cfg -mmin -1)
			fi
			echo "${rc}" | grep grub.cfg
			check $?
		fi
	fi
}

function ask_package_install {
	echo "##################################################"
	echo ""
	echo "Ready to Install packages?"
	echo ""
	echo "Press Enter to continue. Or Ctrl-c to quit."
	read line
}

function remove_junk_rpms {
	echo "##################################################"
	echo "Removing unecessary packages"
	list="thunderbird transmission ktorrent"
	remove_list "${list}" "Nothing to remove -                      Skipping."
	sleep 1
}

function install_rpm_fusion_free {
	echo "##################################################"
	echo "Installing RPM Fusion Free Repository"
	count=$(echo "${RPMLIST}" | grep "rpmfusion-free-release" | wc -l)
	if [ ! ${count} -eq 1 ]; then
		dnf -y ${DNF_OPTIONS} install https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm
		check $?
	else
		echo "RPM Fusion Free Already Installed -           Skipping."
	fi
}

function install_rpm_fusion_nonfree {
	echo "##################################################"
	echo "Installing RPM Fusion Non-Free Repository"
	count=$(echo "${RPMLIST}" | grep "rpmfusion-nonfree-release" | wc -l)
	if [ ! ${count} -eq 1 ]; then
		dnf -y ${DNF_OPTIONS} install https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm
		check $?
	else
		echo "RPM Fusion Non-Free Already Installed -           Skipping."
	fi
}
function install_system_utils {
	echo "##################################################"
	echo "Installing System Utilities"
	list="pavucontrol gparted fwupd flameshot screen xclip"
	#list="pavucontrol samba gparted htop fuse-exfat nmap postfix thinkfan fwupd"
	install_list "${list}" "System Utilities already Installed -     Skipping."
}

function install_vim {
	echo "##################################################"
	echo "Installing Vim"
	list="vim"
	install_list "${list}" "Vim already Installed -                  Skipping."
}

function install_emacs {
	echo "##################################################"
	echo "Installing Emacs"
	list="emacs"
	install_list "${list}" "Emacs already Installed -                  Skipping."
}

function install_libreoffice {
	echo "##################################################"
	echo "Installing Libreoffice"
	list="libreoffice"
	install_list "${list}" "libreoffice already Installed -           Skipping."
}

function install_samba {
	echo "##################################################"
	echo "Installing Samba"
	list="samba"
	install_list "${list}" "Samba already Installed -                Skipping."
}

function install_applications {
	echo "##################################################"
	echo "Installing Various Applications"
	#list="putty rdesktop screen evince eog ImageMagick libreoffice icecat xscreensaver filezilla pidgin dconf-editor remmina xclip gimp clementine mpg123 flameshot keepassx p7zip p7zip-plugins stress"
	list="putty rdesktop evince eog ImageMagick libreoffice xscreensaver filezilla pidgin dconf-editor remmina xclip gimp clementine mpg123 keepassx p7zip p7zip-plugins stress"
	install_list "${list}" "Various Applications already Installed - Skipping."
}

function install_msttcore_fonts {
	echo "##################################################"
	echo "Installing MS True Type Fonts 2.6-1"
	rc=$(echo "${RPMLIST}" | grep -w "msttcore-fonts-installer") 
	if [ ! $? -eq 0 ] ; then 
		dnf -y ${DNF_OPTIONS} install cabextract https://downloads.sourceforge.net/project/mscorefonts2/rpms/msttcore-fonts-installer-2.6-1.noarch.rpm
		check $?
	else
		echo "MS True Type Fonts already Installed -   Skipping."
	fi
}

function install_rpm_utilities {
	echo "##################################################"
	echo "Installing RPM Utilities"
	list="rpmdevtools cmake koji rpmconf xz-devel xz-lzma-compat bzip2-devel dnf-utils qt3-devel libXi-devel fedpkg fedora-packager ncurses-devel pesign"
	install_list "${list}" "RPM Utilities already Installed -        Skipping."
}

function group_install_c_development_tools {
	echo "##################################################"
	echo "Installing Group - C Development Tools and Libraries"
	install_group "C Development Tools and Libraries"
}

function group_install_development_tools {
	echo "##################################################"
	echo "Installing Group - Development Tools"
	install_group "Development Tools"
}

# Virtualization group might be broken
function group_install_virtualization {
	echo "##################################################"
	echo "Installing Group - Virtualization"
	install_group "Virtualization"
}

function install_virtualization_utils {
	echo "##################################################"
	echo "Installing Virtualization Utilities"
	list="virt-manager qemu spice-vdagent virt-viewer remmina-plugins-spice spice-gtk-tools"
	install_list "${list}" "Virtualization Utils already Installed - Skipping."
}

function install_google_chrome_repository {
	if [[ ! -f /etc/yum.repos.d/google-chrome.repo ]]; then
		echo "##################################################"
		echo "Enabling Google Chrome Repository"
cat <<< '
[google-chrome]
name=google-chrome
baseurl=http://dl.google.com/linux/chrome/rpm/stable/x86_64
enabled=1
gpgcheck=1
gpgkey=https://dl.google.com/linux/linux_signing_key.pub
'> /etc/yum.repos.d/google-chrome.repo
		[ -f /etc/yum.repos.d/google-chrome.repo ]
			check $?
	#else
	#	echo "Google Chrome Repo Already Installed -   Skipping."
	restorecon /etc/yum.repos.d/google-chrome.repo
	fi
}

function install_google_chrome_stable {
	echo "##################################################"
	echo "Installing Google Chrome Stable"
	list="google-chrome-stable"
	install_list "${list}" "Google Chrome Stable Already Installed - Skipping."
}

function install_google_chrome_beta {
	echo "##################################################"
	echo "Installing Google Chrome beta"
	list="google-chrome-beta"
	install_list "${list}" "Google Chrome Beta Already Installed -   Skipping."
}

function install_google_chrome_unstable {
	echo "##################################################"
	echo "Installing Google Chrome Unstable"
	list="google-chrome-unstable"
	install_list "${list}" "Google Chrome Unstable Already Installed Skipping."
}

function install_unresolved_deps {
	if [[ ${FEDORA_VERSION} -lt 32 ]]; then
		echo "##################################################"
		echo "Installing Unresolved Dependencies"
		list="python2-gtkextra pygtk2-libglade"
		install_list "${list}" "Python2 Dependencies already Installed - Skipping."
	fi
	sleep 1
}

function check_nvidia_and_install {
	echo "##################################################"
	echo "Checking for Existence of Nvidia GPU"
	echo ""
	lspci | grep -i "vga\|3d controller" | grep -i nvidia
	if [ $? -eq 0 ]; then
		echo "Nvidia GPU Found."
		echo ""
		echo "##################################################"
		echo "Ensuring Nvidia dependencies are met"
		list="kernel-devel"
		#list="kernel-devel kernel-headers"
		install_list "${list}" "Nvidia dependencies are met -   Skipping."
		echo "##################################################"
		echo "Removing Nouveau Drivers"
		# Generally not needed..but cleaner
		rc=$(echo "${RPMLIST}" | grep -i "nouveau") 
		if [ $? -eq 0 ]; then
			dnf -y ${DNF_OPTIONS} remove \*nouveau\*
			check $?
		else
			echo "Nouveau driver already removed -         Skipping."
		fi

		echo "##################################################"
		echo "Installing Negativo 17 Repository"
		# fedora-nvidia for work, fedora-multimedia for home systems
		[ -f /etc/yum.repos.d/${NVIDIA_REPO_TYPE}.repo ]
		if [ ! $? -eq 0 ]; then
			dnf config-manager --add-repo=https://negativo17.org/repos/${NVIDIA_REPO_TYPE}.repo
			check $?
		else
			echo "Negativo17 Repository Already Installed  Skipping."
		fi
		
		echo "##################################################"
		echo "Installing Nvidia Drivers - Negativo 17"
		list="nvidia-driver nvidia-settings ${NVIDIA_KMOD_TYPE}"
		install_list "${list}" "Nvidia Driver already Installed -        Skipping."
	else
		echo "Nvidia GPU Not Found -                   Skipping."
	fi
}

function ask_system_config {
	echo "##################################################"
	echo ""
	echo "Packages Installed - Ready for System Configuration"
	echo ""
	echo "Press Enter to Continue or Ctrl-c to quit."
	read line
}

function enabling_ssh {
	echo "##################################################"
	echo "Enabling SSH"
	systemctl enable sshd
	check $?
}

function starting_ssh {
	echo "##################################################"
	echo "Starting SSH"
	systemctl restart sshd
	check $?
}

function terminal_gtk_tweaks {
	echo "##################################################"
	echo "Terminal gtk.css tweak to reduce height of tabs"
	echo ""
	file_path="${_HOME}/.config/gtk-3.0"
	filename="gtk.css"
	mkdir -p "${file_path}"
	find ${file_path} -type f | grep -q "${filename}"
	if [ ! $? -eq 0 ]; then

cat <<< '
notebook tab {
  min-height: 0;
  padding-top: 0px;
  padding-bottom: 0px;
}

notebook tab button {
  min-height: 0;
  min-width: 0;
  padding: 0px;
  margin-top: 0px;
  margin-bottom: 0px;
}

notebook button {
  min-height: 0;
  min-width: 0;
  padding: 0px;
}
'> 	${file_path}/${filename}
		chown ${username}.${username} ${file_path}/${filename}
		check $?
	else
		#echo "gtk.css already exists - Skipping."
		echo "${PREV_UPDATE}"
	fi
}

function firewall_rules_samba_libvirt {
	echo "##################################################"
	echo "Setup Firewall rules for Samba sharing via libvirt/KVM"
	# dont bother if there is no libvirt zone as we will fail WST otherwise
	rc=$(firewall-cmd --get-active-zones|grep libvirt)
	if [ ! "${rc}" == "" ]; then
		firewall-cmd --zone=libvirt --add-service=samba
		check $?
		firewall-cmd --runtime-to-permanent
		check $?
	fi
}

function setup_samba_config {
	echo "##################################################"
	echo "Samba Config smb.conf setup"
	file_path="/etc/samba"
	filename="smb.conf"
	grep -q "shared_${username}" ${file_path}/${filename}
	if [ ! $? -eq 0 ]; then
		mv -f ${file_path}/${filename} ${file_path}/${filename}.bak
cat <<< '
[global]
        workgroup = LINUXKVM
        server string = Samba Server Version %v
        interfaces = lo virbr0
        log file = /var/log/samba/log.%m
        max log size = 50
        security = user
        load printers = yes
        cups options = raw
	unix extensions = no
	ntlm auth = yes
	client ntlmv2 auth = yes
[shared_LINUXUSER]
        comment = Linux Home
        path = LINUXUSERHOME
        read only = no
        browseable = yes
        force user = LINUXUSER
        create mask = 0777
        directory mask = 0777
        guest ok = No
        valid users = LINUXUSER
[usb_LINUXUSER]
        comment = USB file space
        path = /run/media
        read only = no
        browseable = yes
        force user = LINUXUSER
        create mask = 0777
        directory mask = 0777
        guest ok = No
        valid users = LINUXUSER

# systemctl enable smb.service
# systemctl restart smb.service
'> ${file_path}/${filename}
		grep -q "LINUXUSERHOME" ${file_path}/${filename}
		if [ $? == 0 ]; then
			sedhome=$(echo ${_HOME}|sed 's/\//\\\//g')
			perl -pi -e "s/LINUXUSERHOME/${sedhome}/g" ${file_path}/${filename}
			grep -q "${_HOME}" ${file_path}/${filename}
			check $?
		fi
		grep -q "LINUXUSER" ${file_path}/${filename}
		if [ $? == 0 ]; then
			perl -pi -e "s/LINUXUSER/${username}/g" ${file_path}/${filename}
			grep -q "${username}" ${file_path}/${filename}
			check $?
		fi
	else
		#echo "smb.conf already set up -                Skipping."
		echo "${PREV_UPDATE}"
	fi
}

function enabling_samba {
	echo "##################################################"
	echo "Enabling Samba"
	systemctl enable smb
	check $?
}

function starting_samba {
	echo "##################################################"
	echo "Starting samba"
	systemctl restart smb
	check $?
}

function generate_samba_account {
	echo "##################################################"
	echo "Generating SMB Account for Windows Fileshares"
	echo ""
	pdbedit -w -L | awk -F":" '{ print $1 }' | grep -q "${username}$"
	if [ ! $? -eq 0 ]; then
		echo ""
		echo "Syncing SMB Password with Laptop user account ${username}"
		(echo "${password}"; echo "${password}") | smbpasswd -sa ${username}
		check $?
	else
		echo "Username: ${username}"
		echo "SMB Account already exists -             Skipping."
	fi
}

function bash_history_user {
	echo "##################################################"
	echo "Setting up Bash History for user"
	echo ""
	file_path=${_HOME}
	filename=.bashrc
	grep -q HISTSIZE ${file_path}/${filename}
	if [ ! $? -eq 0 ]; then
	cat <<<'
export HISTTIMEFORMAT="%Y%m%d %T "
export HISTFILESIZE=-1
export HISTSIZE=-1
'>> ${file_path}/${filename}
		grep -q HISTSIZE ${file_path}/${filename}
		check $?
	else
		#echo "Bash History already set - Skipping."
		echo "${PREV_UPDATE}"
	fi
}

function bash_history_root {
	echo "##################################################"
	echo "Setting up Bash History for root"
	echo ""
	file_path=/root
	filename=.bashrc
	grep -q HISTSIZE ${file_path}/${filename}
	if [ ! $? -eq 0 ]; then
	cat <<<'
export HISTTIMEFORMAT="%Y%m%d %T "
export HISTFILESIZE=-1
export HISTSIZE=-1
'>> ${file_path}/${filename}
		grep -q HISTSIZE ${file_path}/${filename}
		check $?
	else
		#echo "Bash History already set - Skipping."
		echo "${PREV_UPDATE}"
	fi
}

function run_rpmconf {
	echo "##################################################"
	echo "Running rpmconf to clean up config files"
	rpmconf -a
}

########### IBMIFICATION ############
# Lets keep the gsa repo disabled, and use --enablerepo=openclient.gsa when we need to use it.
function install_fedora_openclient_gsa_repository {
	echo "##################################################"
	echo "Enabling Fedora OpenClient GSA Repository"
	if [[ ! -f /etc/yum.repos.d/openclient-gsa.repo ]]; then
cat <<< '
[openclient-gsa]
name=Open Client for Fedora (GSA) $releasever
baseurl=http://pokgsa.ibm.com/projects/o/openclient-softdist/yum/fedora/$releasever/$basearch/
enabled=0
gpgcheck=0
skip_if_unavailable=1
'> /etc/yum.repos.d/openclient-gsa.repo 
		restorecon /etc/yum.repos.d/openclient-gsa.repo
		# Always disabled, lets use --enablerepo when we need it
		#if [ "${ALREADY_CONNECTED}" == "true" ]; then
		#	# Installing, but disabling as we dont need it now.
		#	perl -pi -e 's/enabled=1/enabled=0/g' /etc/yum.repos.d/openclient-gsa.repo
		#fi
	else
		echo "OpenClient GSA Repo Already Installed -  Skipping."
	fi
	sleep 1
}

function install_slack_repository {
	echo "##################################################"
	echo "Enabling Slack Repository"
	if [[ ! -f /etc/yum.repos.d/slack.repo ]]; then
cat <<< '
[slack]
name=slack
baseurl=https://packagecloud.io/slacktechnologies/slack/fedora/21/x86_64
enabled=1
gpgcheck=0
gpgkey=https://packagecloud.io/gpg.key
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
'> /etc/yum.repos.d/slack.repo
		[ -f /etc/yum.repos.d/slack.repo ]
			check $?
	else
		echo "Slack Repo Already Installed -           Skipping."
	fi
}

function install_slack {
	echo "##################################################"
	echo "Installing slack"
	list="slack"
	install_list "${list}" "Slack already Installed -                Skipping."
}

function install_skype_repository {
	echo "##################################################"
	echo "Enabling Skype Repository"
	if [[ ! -f /etc/yum.repos.d/skype-stable.repo ]]; then
cat <<< '
[skype-stable]  
name=skype (stable)  
baseurl=https://repo.skype.com/rpm/stable/  
enabled=1  
gpgcheck=1  
gpgkey=https://repo.skype.com/data/SKYPE-GPG-KEY
'> /etc/yum.repos.d/skype-stable.repo
		[ -f /etc/yum.repos.d/skype-stable.repo ]
			check $?
	else
		echo "Skype Repo Already Installed -           Skipping."
	fi
}

function install_skype {
	echo "##################################################"
	echo "Installing Skype"
	list="skypeforlinux"
	install_list "${list}" "Skype already Installed -                Skipping."
}

function install_msft_teams_repository {
	echo "##################################################"
	echo "Enabling Microsoft Teams Repository"
	rpm --import https://packages.microsoft.com/keys/microsoft.asc
	if [[ ! -f /etc/yum.repos.d/teams.repo ]]; then
cat <<< '
[teams]
name=teams
baseurl=https://packages.microsoft.com/yumrepos/ms-teams
enabled=1
gpgcheck=1
gpgkey=https://packages.microsoft.com/keys/microsoft.asc
'> /etc/yum.repos.d/teams.repo
		[ -f /etc/yum.repos.d/teams.repo ]
			check $?
	else
		echo "Microsoft Teams Repo Already Installed -           Skipping."
	fi
}

function install_msft_teams {
	echo "##################################################"
	echo "Installing Microsoft Teams"
	list="teams"
	install_list "${list}" "Microsoft Teams already Installed -                Skipping."
}

function install_msft_visual_studio_code_repository {
	echo "##################################################"
	echo "Enabling Microsoft Visual Studio Code Repository"
	rpm --import https://packages.microsoft.com/keys/microsoft.asc
	if [[ ! -f /etc/yum.repos.d/vscode.repo ]]; then
cat <<< '
[code]
name=Visual Studio Code
baseurl=https://packages.microsoft.com/yumrepos/vscode
enabled=1
gpgcheck=1
gpgkey=https://packages.microsoft.com/keys/microsoft.asc
'> /etc/yum.repos.d/vscode.repo
		[ -f /etc/yum.repos.d/vscode.repo ]
			check $?
	else
		echo "Microsoft Visual Studio Code Repo Already Installed -           Skipping."
	fi
}

function install_msft_visual_studio_code {
	echo "##################################################"
	echo "Installing Microsoft Visual Studio Code"
	list="code"
	install_list "${list}" "Microsoft Visual Studio Code already Installed -                Skipping."
}

function install_atom_editor_repository {
	echo "##################################################"
	echo "Enabling Atom Editor Repository"
	rpm --import https://packagecloud.io/AtomEditor/atom/gpgkey
	if [[ ! -f /etc/yum.repos.d/atom.repo ]]; then
cat <<< '
[Atom]
name=Atom Editor
baseurl=https://packagecloud.io/AtomEditor/atom/el/7/$basearch
enabled=1
gpgcheck=0
repo_gpgcheck=1
gpgkey=https://packagecloud.io/AtomEditor/atom/gpgkey
'> /etc/yum.repos.d/atom.repo
		[ -f /etc/yum.repos.d/atom.repo ]
			check $?
	else
		echo "Atom Editor Repo Already Installed -           Skipping."
	fi
}

function install_atom_editor {
	echo "##################################################"
	echo "Installing Atom Editor"
	list="atom"
	install_list "${list}" "Atom Editor already Installed -                Skipping."
}

function install_ibm_utilities {
	echo "##################################################"
	echo "Installing IBM Utilities"
	list="phone ibm-openconnect toxsocks ibmplexfonts ibmfonts"
	install_list "${list}" "IBM Utilities already Installed -        Skipping."
}

function install_ibm_java {
	echo "##################################################"
	echo "Installing IBM Java"
	# need to echo RPMLIST
	javalist=$(rpm -qa | grep -i java| grep ibm)
	list="java-1.8.0-ibm java-1.8.0-ibm-plugin java-1.8.0-ibm-devel"
	install_list "${list}" "IBM Java already Installed -             Skipping."
#	if [ $? -eq 0 ]; then 
#		echo "Select IBM Java"
#		alternatives --config java
#	fi
}

function group_install_ibm_client_base {
	echo "##################################################"
	echo "Installing Group - IBM Client Base"
	install_group "IBM Client Base"
}

function group_install_ibm_firewall_rules {
	echo "##################################################"
	echo "Installing Group - IBM Firewall Rules"
	install_group "IBM Firewall Rules" 
}

function group_install_ibm_workstation_security_tool {
	echo "##################################################"
	echo "Installing Group - IBM Workstation Security Tool"
	install_group "IBM Workstation Security Tool"
}

function group_install_ibm_security_compliance {
	echo "##################################################"
	echo "Installing Group - IBM Security Compliance"
	install_group "IBM Security Compliance"
}

function group_install_ibm_openconnect {
	echo "##################################################"
	echo "Installing Group - IBM Openconnect"
	install_group "IBM Openconnect"
}

function group_install_ibm_vpn {
	echo "##################################################"
	echo "Installing Group - IBM VPN"
	install_group "IBM VPN"
}

function group_install_ec_print {
	echo "##################################################"
	echo "Installing Group - IBM EC Print"
	[ -f /var/opt/openclient/ibm-c4eb-install-info ]
	if [ $? -eq 0 ]; then
		grep -q "${w3user}" /var/opt/ibmsam/registry.ini
		if [ $? -eq 0 ]; then
			install_group "IBM EC Print"
		else
			echo "You need to register with ISAM before installing printers"
			check 1
		fi
	else
		echo "You need to Register before installing this software"
		run_ibmregtool_cmd
	fi
}

function group_install_ibm_Licensed {
	echo "##################################################"
	echo "Installing Group - IBM Licensed"
	[ -f /var/opt/openclient/ibm-c4eb-install-info ]
	if [ $? -eq 0 ]; then
		grep -q "${w3user}" /var/opt/ibmsam/registry.ini
		if [ $? -eq 0 ]; then
			install_group "IBM Licensed"
		else
			echo "You need to register with ISAM before installing the Licensed Repo"
			check 1
		fi
	else
		echo "You need to Register before installing this software"
		run_ibmregtool_cmd
	fi
}

function group_install_ibm_notes {
	echo "##################################################"
	echo "Installing Group - IBM Notes"
	install_group "IBM Notes"
}

function group_install_ibm_crashplan {
	echo "##################################################"
	echo "Installing Group - IBM Crashplan"
	[ -f /var/opt/openclient/ibm-c4eb-install-info ]
	if [ $? -eq 0 ]; then
		grep -q "${w3user}" /var/opt/ibmsam/registry.ini
		if [ $? -eq 0 ]; then
			install_group "IBM Crashplan"
		else
			echo "You need to register with ISAM before installing CrashPlan"
			check 1
		fi
	else
		echo "You need to Register before installing this software"
		run_ibmregtool_cmd
	fi
}

function ask_reboot {
	echo "##################################################"
	echo "System needs to reboot"
	echo "You can continue to run this script again after rebooting"
	echo ""
	echo "Press Enter to reboot or Ctrl-c to Cancel"
	read line
	reboot
}

function run_ibmregtool {
	clear
	echo "##################################################"
	echo "Running IBM Reg Tool"
	echo ""
	echo "You must register your w3ID in order to obtain a VPN Certificate!"
	echo ""
	echo "If the Registration Tool does not appear, then your X/Wayland"
	echo "session crashed. If so, Ctrl-C this script, Reboot or Logout/Log back in,"
	echo "and then re-run this script."
	[ -f /var/opt/openclient/ibm-c4eb-install-info ]
	if [ ! $? -eq 0 ]; then
		rc=$(/usr/bin/python /usr/share/ibmregtool/ibmregtool.py 2>&1 >/dev/null)
		[ -f /var/opt/openclient/ibm-c4eb-install-info ]
		if [ $? -eq 0 ]; then
			echo "                                          Success."
		else
			echo "Error - You must register in order to obtain a VPN Certificate"
		fi
		
	else
		echo "System is Already Registered -           Skipping."
	fi
}

function run_ibmregtool_cmd {
	clear
	echo "##################################################"
	echo "Running IBM Reg Tool"
	echo ""
	echo "Registering with ibmregtool.py - pre-requisite to obtain an IBM VPN Cert."
	echo ""
	[ -f /var/opt/openclient/ibm-c4eb-install-info ]
	if [ ! $? -eq 0 ]; then
		#rc=$(/usr/bin/python /usr/share/ibmregtool/ibmregtool.py -r ${w3user} 2>&1 >/dev/null)
		status "/usr/bin/python /usr/share/ibmregtool/ibmregtool.py -r ${w3user} 2>&1 >/dev/null" 'Please wait'
		[ -f /var/opt/openclient/ibm-c4eb-install-info ]
		if [ $? -eq 0 ]; then
			echo "                                          Success."
		else
			echo "Error - You must register in order to obtain a VPN Certificate"
		fi
		
	else
		echo "System is Already Registered -           Skipping."
	fi
}
function disable_openclient_repo {
	if [ ! "${ALREADY_CONNECTED}" == "true" ]; then
		echo "##################################################"
		echo "Disabling openclient.repo temporarily during build stage"
		echo "As we do not have access to it on the IBM W3 VPN"
		echo "We will use GSA for Now"
		echo ""
		grep -q "^enabled=0$" /etc/yum.repos.d/openclient.repo
		if [ ! $? == 0 ]; then
			perl -pi -e 's/enabled=1/enabled=0/g' /etc/yum.repos.d/openclient.repo
			grep -q "^enabled=0$" /etc/yum.repos.d/openclient.repo
			check $?
		else
			echo "${PREV_UPDATE}"
		fi
	fi
	sleep 1
}

# Original registry.ini
#[isam]
#WakeupDate=2020108
#WakeupTime=1233
#LastScanSequenceNumber=1
#[WstMiniScans]
#MiniScanDate=
#MiniScans=

# valid ini that got a vpn cert
#[isam]
#Preregistered = 1
#WorkstationUseSelected = 1
#WakeupDate=2020108
#WakeupTime=950
#LastScanSequenceNumber=3
#[user]
#IntranetID = oteri@us.ibm.com
#WorkstationUse = Secondary Workstation
#WorkstationUseAbbrev = SECONDARY
#Geography = US
#jobRole = STD
#MachineType = PHYSICAL
#Owner = IBM
#PhysicalDevice = LAPTOP
#SecType2 = NONE
#SecType = 3
#PreviousSecType = 0
#SecTypeChangeDate = 20200416
#[system]
#OpsysName=Fedora release 31 (Thirty One)
#CebImageName=Open Client Fedora 31 (Daily)
#[bluepages]
#uid =
#[WstMiniScans]


function isam_geography {
	echo ""
	echo "### Please choose from the following ###"
	echo ""
	geo=(	'US'	\
		'EMEA'	\
		'LA'	\
		'AP'	\
		'Canada')
	PS3=$'\n'"What is your IBM Geography? "
	select opt in "${geo[@]}"; do
		case "${opt}" in
			'US')
				GEOGRAPHY="US"
				;;
			'EMEA')
				GEOGRAPHY="EMEA"
				;;
			'LA')
				GEOGRAPHY="LA"
				;;
			'AP')
				GEOGRAPHY="AP"
				;;
			'Canada')
				GEOGRAPHY="Canada"
				;;
			*)
				GEOGRAPHY="INVALID"
				;;
		esac
		if [ ! "${GEOGRAPHY}" == "INVALID" ]; then
			echo ""
			echo "You have selected IBM Geography: ${opt}"
			read -p "Is this correct? [Y/N]: " validate
			echo ""
			rc=$(echo "${validate}"| grep -qi "^y")
			if [ $? -eq 0 ]; then 
				break
			fi
		fi
		PS3=""
		echo ""
		echo "### Please choose from the following ###"
		echo ""
		echo 1 | select opt in "${geo[@]}"; do break; done
		PS3=$'\n'"What is your IBM Geography? "
	done
}

function isam_job_role {
	echo ""
	echo "### Please choose from the following ###"
	echo ""
	job_role=(	'Standard User'		\
			'Privileged User'	\
			'Service Center/Call Center User')
	PS3=$'\n'"What is your job role when using this workstation device? "
	select opt in "${job_role[@]}"; do
		case "${opt}" in
			'Standard User')
				JOBROLE="STD"
				;;
			'Privileged User')
				JOBROLE="PRIV"
				;;
			'Service Center/Call Center User')
				JOBROLE="SVCCALLCTR"
				;;
			*)
				JOBROLE="INVALID"
				;;
		esac
		if [ ! "${JOBROLE}" == "INVALID" ]; then
			echo ""
			echo "You have selected Job Role: ${opt}"
			read -p "Is this correct? [Y/N]: " validate
			echo ""
			rc=$(echo "${validate}"| grep -qi "^y")
			if [ $? -eq 0 ]; then 
				break
			fi
		fi
		PS3=""
		echo ""
		echo "### Please choose from the following ###"
		echo ""
		echo 1 | select opt in "${job_role[@]}"; do break; done
		PS3=$'\n'"What is your job role when using this workstation device? "
	done
}


function isam_workstation_usage {
	echo ""
	echo "### Please choose from the following ###"
	echo ""
	work_usage=(	'Primary Workstation'	\
			'Secondary Workstation'	\
			'Shared Workstation'	\
			'Classroom Workstation'	\
			'Lab Workstation'	\
			'Application Server'	\
			'Infrastructure Server'	\
			'Lab Server'		\
			'Loaner Workstation'	\
			'Commercial Project Device (Japan Only)')

	PS3=$'\n'"This Workstation used in which capacity? "
	select opt in "${work_usage[@]}"; do
		case "${opt}" in
			'Primary Workstation')
				WorkstationUseAbbrev="PRIMARY"
				WorkstationUse="${opt}"
				;;
			'Secondary Workstation')
				WorkstationUseAbbrev="SECONDARY"
				WorkstationUse="${opt}"
				;;
			'Shared Workstation')
				WorkstationUseAbbrev="SHARED"
				WorkstationUse="${opt}"
				;;
			'Classroom Workstation')
				WorkstationUseAbbrev="CLASS"
				WorkstationUse="${opt}"
				;;
			'Lab Workstation')
				WorkstationUseAbbrev="LAB"
				WorkstationUse="${opt}"
				;;
			'Application Server')
				WorkstationUseAbbrev="UNK"
				WorkstationUse="${opt}"
				;;
			'Infrastructure Server')
				WorkstationUseAbbrev="UNK"
				WorkstationUse="${opt}"
				;;
			'Lab Server')
				WorkstationUseAbbrev="UNK"
				WorkstationUse="${opt}"
				;;
			'Loaner Workstation')
				WorkstationUseAbbrev="LOANER"
				WorkstationUse="${opt}"
				;;
			'Commercial Project Device (Japan Only)')
				WorkstationUseAbbrev="COMMERCIAL"
				WorkstationUse="${opt}"
				;;
			*)
				WorkstationUseAbbrev="INVALID"
				WorkstationUse="${opt}"
				;;
		esac
		if [ ! "${WorkstationUse}" == "INVALID" ]; then
			echo ""
			echo "You have selected Workstation Usage: ${opt}"
			read -p "Is this correct? [Y/N]: " validate
			echo ""
			rc=$(echo "${validate}"| grep -qi "^y")
			if [ $? -eq 0 ]; then 
				break
			fi
		fi
		PS3=""
		echo ""
		echo "### Please choose from the following ###"
		echo ""
		echo 1 | select opt in "${work_usage[@]}"; do break; done
		PS3=$'\n'"This Workstation used in which capacity? "
	done
}

function isam_owner {
	echo ""
	echo "### Please choose from the following ###"
	echo ""
	laptop_owner=(	'IBM Provided'					\
			'Personally Owned'				\
			'3rd Party Owned - Vendor Provided'		\
			'3rd Party Owned - Contractor Agency Provided'	\
			'3rd Party Owned - Client Provided')
	PS3=$'\n'"Who owns or provides this workstation device? "
	select opt in "${laptop_owner[@]}"; do
		case "${opt}" in
			'IBM Provided')
				OWNER="IBM"
				;;
			'Personally Owned')
				OWNER="PERSONAL"
				;;
			'3rd Party Owned - Vendor Provided')
				OWNER="VENDOR"
				;;
			'3rd Party Owned - Contractor Agency Provided')
				OWNER="CONTRACTOR"
				;;
			'3rd Party Owned - Client Provided')
				OWNER="CLIENT"
				;;
			*)
				OWNER="INVALID"
				;;
		esac
		if [ ! "${OWNER}" == "INVALID" ]; then
			echo ""
			echo "You have selected the Laptop Owner as: ${opt}"
			read -p "Is this correct? [Y/N]: " validate
			echo ""
			rc=$(echo "${validate}"| grep -qi "^y")
			if [ $? -eq 0 ]; then 
				break
			fi
		fi
		PS3=""
		echo ""
		echo "### Please choose from the following ###"
		echo ""
		echo 1 | select opt in "${laptop_owner[@]}"; do break; done
		PS3=$'\n'"Who owns or provides this workstation device? "
	done
}

function isam_machine_type {
	echo ""
	echo "### Please choose from the following ###"
	echo ""
	machine_type=(	'Physical Workstation'
			'Virtual Machine')
	PS3=$'\n'"Are you registering a virtual machine, i.e. VMware, or a physical workstation? "
	select opt in "${machine_type[@]}"; do
		case "${opt}" in
			'Physical Workstation')
				MachineType="PHYSICAL"
				;;
			'Virtual Machine')
				MachineType="VIRTUAL"
				;;
			*)
				MachineType="INVALID"
				;;
		esac
		if [ ! "${MachineType}" == "INVALID" ]; then
			echo ""
			echo "You have indicated this Device is a : ${opt}"
			read -p "Is this correct? [Y/N]: " validate
			echo ""
			rc=$(echo "${validate}"| grep -qi "^y")
			if [ $? -eq 0 ]; then 
				break
			fi
		fi
		PS3=""
		echo ""
		echo "### Please choose from the following ###"
		echo ""
		echo 1 | select opt in "${machine_type[@]}"; do break; done
		PS3=$'\n'"Are you registering a virtual machine, i.e. VMware, or a physical workstation? "
	done
}

function isam_physical_device {
	echo ""
	echo "### Please choose from the following ###"
	echo ""
	physical_device=(	'Workstation - Desktop'				\
				'Workstation - Laptop'				\
				'Workstation - Thinclient'			\
				'Server'					\
				'Smartphone / Tablet / Other Mobile Device'	\
				'Printer / Copier / Fax / Multifunction'	\
				'Voice Over IP Device'				\
				'Other (Device not listed)')
	PS3=$'\n'"What type of physical device is your workstation? On a virtual machine, answer for the hosting device. "
	select opt in "${physical_device[@]}"; do
		case "${opt}" in
			'Workstation - Desktop')
				PhysicalDevice='DESKTOP'
				;;
			'Workstation - Laptop')
				PhysicalDevice='LAPTOP'
				;;
			'Workstation - Thinclient')
				PhysicalDevice='THINCLIENT'
				;;
			'Server')
				PhysicalDevice='SERVER'
				;;
			'Smartphone / Tablet / Other Mobile Device')
				PhysicalDevice='PHONETAB'
				;;
			'Printer / Copier / Fax / Multifunction')
				PhysicalDevice='PRINTCOPY'
				;;
			'Voice Over IP Device')
				PhysicalDevice='VOIP'
				;;
			'Other (Device not listed)')
				PhysicalDevice='OTHER'
				;;
			*)
				PhysicalDevice="INVALID"
				;;
		esac
		if [ ! "${PhysicalDevice}" == "INVALID" ]; then
			echo ""
			echo "You have indicated this Device is a : ${opt}"
			read -p "Is this correct? [Y/N]: " validate
			echo ""
			rc=$(echo "${validate}"| grep -qi "^y")
			if [ $? -eq 0 ]; then 
				break
			fi
		fi
		PS3=""
		echo ""
		echo "### Please choose from the following ###"
		echo ""
		echo 1 | select opt in "${physical_device[@]}"; do break; done
		PS3=$'\n'"What type of physical device is your workstation? On a virtual machine, answer for the hosting device. "
	done
}

# Toggles the selected pick on or off
function pick {
	index=${1}
	if [[ ${selected[${index}]} ]]; then
 		selected[${index}]=''
	else
		selected[${index}]='+'
	fi
}

# Select all picks
function select_all_picks {
	index=${1}
	for i in $(seq 1 ${index}); do
 		selected[${i}]='+'
	done
}

function clear_all_picks {
	for i in "${!selected[@]}"; do
 		selected[${i}]=''
	done
}
#function clear_all_picks {
#	len=${#selected[@]}
#	for (( i=1; i<${len}+1; i++ )); do
# 		selected[${i}]=''
#	done
#}

# Selecting NONE will clear all existing Picks except for NONE
function clear_all_picks_except {
	index=${1}
	for i in $(seq 1 ${index}); do
 		selected[${i}]=''
	done
	selected[${index}]='+'
}

# Clear a specific pick. Used when you selected something, it unchecks NONE
# as to avoid any errors in selection
function clear_pick {
	index=${1}
	selected[${index}]=''
}

# Multi Selectable Menu for choosing Security Types
function isam_security_type {
	clear_all_picks_except 5
	clear_pick 5
	SecType2=''
	SecType=''
	tmpSecType2=''
	PS3=$'\n'"Please check all of the data types which may be stored on this workstation."$'\n'"You may check multiple items, or alternatively, check \"None of the Above\""$'\n'"if none of these data types may be stored on this workstation."$'\n'$'\n'"Select / Deselect one item at a time: "
	while true ; do
		clear
		echo "### Select All that Apply ###"
		echo ""
		security_type=(	"Sensitive Personal Information (SPI) [${selected[1]}]"			\
				"Client Data [${selected[2]}]"						\
				"Government Regulated Data [${selected[3]}]"				\
				"Federal Financial Institutions Examination Council [${selected[4]}]"	\
				"None of the above [${selected[5]}]"					\
				"Done")
		select opt in "${security_type[@]}"; do
			case $opt in
				"Sensitive Personal Information (SPI) [${selected[1]}]")
					pick 1
					clear_pick 5
					break
					;;
				"Client Data [${selected[2]}]")
					pick 2
					clear_pick 5
					break
					;;
				"Government Regulated Data [${selected[3]}]")
					pick 3
					clear_pick 5
					break
					;;
				"Federal Financial Institutions Examination Council [${selected[4]}]")
					pick 4
					clear_pick 5
					break
					;;
				"None of the above [${selected[5]}]" )
					clear_all_picks_except 5
					break
					;;
				"Done")
					break 2
					;;
				*)
					break
					;;
			esac
		done
	done

	for opt in "${!selected[@]}"; do
		if [[ ${selected[opt]} ]]; then
			if [[ "${SecType2}" == "" ]]; then
				# This did not like being in a case statement, had to break it out
				# it could just have been because it was 2am - yep likely
				if [ ${opt} -eq 1 ]; then SecType2="SPI"	; fi
				if [ ${opt} -eq 2 ]; then SecType2="CLIENT"	; fi
				if [ ${opt} -eq 3 ]; then SecType2="GOVT"	; fi
				if [ ${opt} -eq 4 ]; then SecType2="FFIEC"	; fi
				if [ ${opt} -eq 5 ]; then SecType2="NONE"	; fi
			else
				if [ ${opt} -eq 1 ]; then SecType2=$(echo "${SecType2}|SPI")	; fi
				if [ ${opt} -eq 2 ]; then SecType2=$(echo "${SecType2}|CLIENT")	; fi
				if [ ${opt} -eq 3 ]; then SecType2=$(echo "${SecType2}|GOVT")	; fi
				if [ ${opt} -eq 4 ]; then SecType2=$(echo "${SecType2}|FFIEC")	; fi
				if [ ${opt} -eq 5 ]; then SecType2=$(echo "${SecType2}|NONE")	; fi
			fi
		fi
	done

	# Logic for Security Type Class taken from RHEL, SPI=1, NONE=3, everything else is 2
	if [[ "$(echo ${SecType2} | grep -qi SPI ; echo $?)" == "0" ]]; then
		SecType=1
	elif [[ "$(echo ${SecType2} | grep -qi NONE ; echo $?)" == "0" ]]; then
		SecType=3
	else
		SecType=2
	fi
		
}

function isam_os_levels {
	OpsysName=$(cat /etc/redhat-release)
	CebImageName=$(cat /etc/openclient-release)
}

function restart_bes_client {
	echo "##################################################"
	echo "Restarting BES Client to pick up New Registration"
	status "systemctl restart besclient" "Please wait"
	#check $?
}

function isam_write_registry_ini {
	# need to write out a file to look for so we dont keep rebuilding this file
	# if the .vpn-registered file is found.. either skip or ask the user
	# to force overwrite
	echo "##################################################"
	echo "Writing out ISAM Registration file"
	RUN_TIME=$(date +%Y%m%d)
	SecTypeChangeDate="SecTypeChangeDate = ${RUN_TIME}"
	PreviousSecType="PreviousSecType = 0"
	ini=/var/opt/ibmsam/registry.ini
	if [[ -f "${ini}" ]]; then
		echo "Copying ${ini} to backup ${ini}.$$"
		cp -f "${ini}" "${ini}.$$"
		if [ "$(grep -qi ${w3user} ${ini}; echo $?)" == "0" ]; then
			echo "Looks like you've registered before...Saving some previous data."
			PreviousSecType=$(grep -w SecType ${ini})
			if [ "${PreviousSecType}" == "SecType = ${SecType}" ]; then
				SecTypeChangeDate=$(grep SecTypeChangeDate ${ini})
				PreviousSecType="PreviousSecType = ${SecType}"
			fi
				
		fi
		WakeupDate=$(grep WakeupDate ${ini})
		WakeupTime=$(grep WakeupTime ${ini})
		LastScanSequenceNumber=$(grep LastScanSequenceNumber ${ini})
		echo "[isam]" 						> ${ini}
		echo "Preregistered = 1" 				>> ${ini}
		echo "WorkstationUseSelected = 1" 			>> ${ini}
		echo "${WakeupDate}" 					>> ${ini}
		echo "${WakeupTime}" 					>> ${ini}
		echo "${LastScanSequenceNumber}" 			>> ${ini}
		echo "[user]" 						>> ${ini}
		echo "IntranetID = ${w3user}" 				>> ${ini}
		echo "WorkstationUse = ${WorkstationUse}" 		>> ${ini}
		echo "WorkstationUseAbbrev = ${WorkstationUseAbbrev}" 	>> ${ini}
		echo "Geography = ${GEOGRAPHY}" 			>> ${ini}
		echo "jobRole = ${JOBROLE}" 				>> ${ini}
		echo "MachineType = ${MachineType}"		 	>> ${ini}
		echo "Owner = ${OWNER}"					>> ${ini}
		echo "PhysicalDevice = ${PhysicalDevice}" 		>> ${ini}
		echo "SecType2 = ${SecType2}" 				>> ${ini}
		echo "SecType = ${SecType}" 				>> ${ini}
		echo "${PreviousSecType}" 				>> ${ini}
		echo "${SecTypeChangeDate}" 				>> ${ini}
		echo "[system]" 					>> ${ini}
		echo "OpsysName=${OpsysName}" 				>> ${ini}
		echo "CebImageName=${CebImageName}" 			>> ${ini}
		echo "[bluepages]" 					>> ${ini}
		echo "uid =" 						>> ${ini}
		echo "[WstMiniScans]" 					>> ${ini}
		
		echo ""
		echo "Writing out to registry.ini -            Complete."		

		#restart_bes_client	
	else
		echo "Error: registry.ini file not found. Please ensure you have the OC Fedora base layer installed!"
		ERROR=true
	fi

}

function register_sas_vpn {
	if [ "$(grep -qi ${w3user} /var/opt/ibmsam/registry.ini; echo $?)" == "0" ]; then
		echo "##################################################"
		echo "Existing ISAM Registration Found."
		echo ""
		read -p "Do you want to Re-Answer the ISAM Questions? [Y/N]: " redo_isam
		rc=$(echo "${redo_isam}"| grep -qi "^y")
		if [ ! $? -eq 0 ]; then
			echo ""
			echo "Skipping ISAM Registration"
			return
		fi
	fi
	echo "##################################################"
	echo "IBM SAS VPN Registration"
	echo ""
	echo "Registering VPN for W3 Intranet ID: ${w3user}"
	while true ; do
		isam_geography
		isam_job_role
		isam_workstation_usage
		isam_owner
		isam_machine_type
		isam_physical_device
		while [ "${SecType2}" == "" ];do
			isam_security_type
		done
		isam_os_levels
		echo "##################################################"
		echo ""
		echo "Creating Registration"
		echo "Intranet ID:		${w3user}"
		echo "IBM Geography:		${GEOGRAPHY}"
		echo "Job Role:		${JOBROLE}"
		echo "Workstation Use:	${WorkstationUse}"
		echo "Workstation Use Abbrev:	${WorkstationUseAbbrev}"
		echo "Laptop Owner:		${OWNER}"
		echo "Machine Type:		${MachineType}"
		echo "Device Type:		${PhysicalDevice}"
		echo "Security Type:		${SecType2}"
		echo "Security Class:		${SecType}"
		echo "Operating System Name	${OpsysName}"
		echo "Ceb Image Name		${CebImageName}"
		echo ""
		read -p "Is this Information correct? [Y/N]: " validate
		echo ""
		rc=$(echo "${validate}"| grep -qi "^y")
		if [ $? -eq 0 ]; then 
			isam_write_registry_ini
			break
		fi
	done
}

function get_vpn {
	echo "##################################################"
	echo ""
	echo "Please make note of this Externally Accessible IBM VPN Portal."
	echo ""
	echo "##################################################"
	echo "#   https://mobile.us.ibm.com:15048/tools/vpn/   #"
	echo "##################################################"
	sleep 1
	echo ""
	echo "Your VPN Cert should be available within 45 Minutes to 1 Hour."
	echo -n "ETA: "
	date --date="1 hour"
	sleep 1
	echo ""
	echo "Instructions -->"
	echo "1. Login with your W3ID to access the download page for your VPN Certificate."
	sleep 1
	echo "2. Click on Get Certificate from the above website. Leave it in your ~/Downloads"
	sleep 1
	echo "3. Then Re-Run this script for Stage 2 Setup!"
	sleep 1
	echo -e "\tIt will ask for the password you created during the certificate generation process."
	sleep 1
	echo -e "\tIt will automatically setup your VPN Certificate\n\tand Network Manager VPN Profiles."
	sleep 1
	echo ""
	echo "Press Enter to open FireFox to the VPN Portal. "
	read -p "If the browser does not open, you can navigate to the above site manually. "
	echo ""
	su - ${username} -c 'DISPLAY=:0 firefox https://mobile.us.ibm.com:15048/tools/vpn 2>&1 >/dev/null &'
	echo "IMPORTANT! Make sure to RE-RUN this script after downloading your CERT!"
}

function fix_accounts {
	echo "##################################################"
	echo "Updating Password Expiration for itcs300 compliance"
	# possibly move this to after IBM layer gets installed
	# Fix this function. I don't like it as the user really 
	# needs to possibly change their pw after the IBM Security Rules
	# are installed in order to comply with the 15 char.
	# at some point need to implement luks pw change ocencryptpass
	chage -M -1 -m -1 -W -1 rpc

	chage -l root |grep "Password expires"|grep -q "never"
	if [ $? -eq 0 ]; then 
		echo "Setting Expiration for root"
		chage -M 90 -m 1 root
		echo "$root_password" | passwd --stdin root
		check $?
	else
		echo "User: root"
		echo "${PREV_UPDATE}"
	fi

	chage -l "${username}" |grep "Password expires"|grep -q "never"
	if [ $? -eq 0 ]; then 
		echo "Setting Expiration for ${username}"
		chage -M 90 -m 1 ${username}
		echo "${password}" | passwd --stdin ${username}
		check $?
	else
		echo "User: ${username}"
		echo "${PREV_UPDATE}"
	fi
	sleep 1
}

function finalize {
	echo "################### END ##########################"
	echo ""
	if [ ${ERROR} == true ]; then
		echo "***** Script encountered Errors - Check and re-run *****"
	else
		echo "***** Script Ran Successfully *****"
	fi
	echo ""
}

function write_nmconnection {
cat <<< '
[connection]
id=IBM-LOCATION
uuid=UUIDGEN
type=vpn
autoconnect=false
permissions=

[vpn]
authtype=cert
autoconnect-flags=0
cacert=/usr/share/ibm-config-NetworkManager-openconnect/ibm-vpn-ca-bundle.pem
certsigs-flags=0
cookie-flags=2
csd_wrapper=/usr/share/ibm-config-NetworkManager-openconnect/csd.sh
enable_csd_trojan=yes
gateway=IBMGATEWAY
gateway-flags=2
gwcert-flags=2
lasthost-flags=0
pem_passphrase_fsid=no
prevent_invalid_cert=no
protocol=anyconnect
stoken_source=disabled
usercert=LINUXUSERDOC/IBM_SAS_VPN/ibm-vpn-linux.crt
userkey=LINUXUSERDOC/IBM_SAS_VPN/ibm-vpn-linux.key
xmlconfig-flags=0
service-type=org.freedesktop.NetworkManager.openconnect

[vpn-secrets]
autoconnect=yes
save_passwords=yes

[ipv4]
dns-search=
method=auto

[ipv6]
addr-gen-mode=stable-privacy
dns-search=
ip6-privacy=0
method=disabled

[proxy]

'> ${p12_loc}/IBM-${1}.nmconnection
chmod 600 ${p12_loc}/IBM-${1}.nmconnection
}

function update_profile {
	location="${1}"
	user_name="${2}"
	uuid="${3}"
	ibmgateway="${4}"
	p12_loc="${5}"
	seddoc=$(echo "${_DOCUMENTS}"|sed 's/\//\\\//g')
	perl -pi -e "s/LINUXUSERDOC/${seddoc}/g" ${p12_loc}/IBM-${location}.nmconnection
	perl -pi -e "s/UUIDGEN/${uuid}/g" ${p12_loc}/IBM-${location}.nmconnection
	perl -pi -e "s/IBMGATEWAY/${ibmgateway}/g" ${p12_loc}/IBM-${location}.nmconnection
	perl -pi -e "s/LOCATION/${location}/g" ${p12_loc}/IBM-${location}.nmconnection
}

function write_AMERICA_POK {
	uuid=$(uuidgen)
	ibmgateway=sasvpn.pok.ibm.com
	location=AMERICA-POK
	write_nmconnection ${location}
	update_profile "${location}" "${username}" "${uuid}" "${ibmgateway}" "${p12_loc}"
}

function write_AMERICA_RALEIGH {
	uuid=$(uuidgen)
	ibmgateway=sasvpn.raleigh.ibm.com
	location=AMERICA-RALEIGH
	write_nmconnection ${location}
	update_profile "${location}" "${username}" "${uuid}" "${ibmgateway}" "${p12_loc}"
}

function write_AMERICA_BOULDER {
	uuid=$(uuidgen)
	ibmgateway=sasvpn.boulder.ibm.com
	location=AMERICA-BOULDER
	write_nmconnection ${location}
	update_profile "${location}" "${username}" "${uuid}" "${ibmgateway}" "${p12_loc}"
}

function write_AP_ASEAN {
	uuid=$(uuidgen)
	ibmgateway=sasvpn.au.ibm.com
	location=AP-ASEAN
	write_nmconnection ${location}
	update_profile "${location}" "${username}" "${uuid}" "${ibmgateway}" "${p12_loc}"
}

function write_EUROPE_MEA {
	uuid=$(uuidgen)
	ibmgateway=sasvpn.emea.ibm.com
	location=EUROPE-MEA
	write_nmconnection ${location}
	update_profile "${location}" "${username}" "${uuid}" "${ibmgateway}" "${p12_loc}"
}

function write_EUROPE_MEA_FAST {
	uuid=$(uuidgen)
	ibmgateway=sasvpn-fast.emea.ibm.com
	location=EUROPE-MEA-FAST
	write_nmconnection ${location}
	update_profile "${location}" "${username}" "${uuid}" "${ibmgateway}" "${p12_loc}"
}

function write_INDIA {
	uuid=$(uuidgen)
	ibmgateway=sasvpn.in.ibm.com
	location=INDIA
	write_nmconnection ${location}
	update_profile "${location}" "${username}" "${uuid}" "${ibmgateway}" "${p12_loc}"
}

function write_JAPAN {
	uuid=$(uuidgen)
	ibmgateway=sasvpn.jp.ibm.com
	location=JAPAN
	write_nmconnection ${location}
	update_profile "${location}" "${username}" "${uuid}" "${ibmgateway}" "${p12_loc}"
}

function write_CHINA {
	uuid=$(uuidgen)
	ibmgateway=sasvpn.cn.ibm.com
	location=CHINA
	write_nmconnection ${location}
	update_profile "${location}" "${username}" "${uuid}" "${ibmgateway}" "${p12_loc}"
}

function setup_vpn {
	echo "##################################################"
	echo ""
	echo "Stage2: VPN Setup"
	echo ""
	echo "Find and Split your .p12 Certificate."
	echo "Set up Regional NetworkManager VPN Profiles."
	echo "Optionally, Set up Certs for Cisco Anyconnect."
	echo ""
	check_account USER "Fedora Laptop/Workstation Username"
	mkdir -p ${_DOCUMENTS}/IBM_SAS_VPN
	chown ${username}.${username} ${_DOCUMENTS}/IBM_SAS_VPN
	chmod 755 ${_DOCUMENTS}/IBM_SAS_VPN
	currdir=$(pwd)
	cd ${_DOCUMENTS}/IBM_SAS_VPN
	# Look for the latest valid p12 in the user's Downloads directory
	Download="${_DOWNLOADS}/"$(ls -1tr "${_DOWNLOADS}" | grep  "^ibm-vpn-linux.*.p12$" | tail -1)
	if [ "${Download}" == "" ]; then
		echo "Error Could not find a p12 vpn certificate"
		echo "Please ensure you have downloaded your VPN cert from"
		echo ""
		echo "https://mobile.us.ibm.com:15048/tools/vpn/"
		echo ""
		echo "and then rerun this script."
		exit 1
	fi
	echo""
	echo "Found Certificate: ${Download}"
	echo ""
	file_name=$(basename ${Download})
	p12_loc="${_DOCUMENTS}/IBM_SAS_VPN"

	cp -f "${Download}" .
	chown ${username}.${username} "${file_name}"
	chmod 600 "${file_name}"
	read -s -p "Type in the VPN Password that you just set on the VPN Devices Website: " password
	echo
	openssl pkcs12 -nokeys -clcerts -in "${file_name}" -out ibm-vpn-linux.crt -passin pass:"$password"
	check $?
	openssl pkcs12 -nocerts -nodes -in "${file_name}" -out ibm-vpn-linux.key -passin pass:"$password" -passout pass:"$password"
	check $?
	chown ${username}.${username} ibm-vpn-linux.crt ibm-vpn-linux.key
	chmod 600 ibm-vpn-linux.crt ibm-vpn-linux.key
	if [[ $? -eq 0 ]]; then
		echo "					  Success."
	else
		echo "Cert Error: Most likely a password issue with your certificate."
	fi
	ls -lhtr ibm-vpn-linux.crt ibm-vpn-linux.key
	echo ""
	read -p "VPN Certificate successfully split - Press Enter to continue."
	write_vpn_region
	# These always work
	#write_AMERICA_POK
	#write_EUROPE_MEA
	#write_EUROPE_MEA_FAST
	#write_AP_ASEAN
	#write_JAPAN
	# Boulder and Raleigh now work!
	#write_AMERICA_RALEIGH
	#write_AMERICA_BOULDER
	# Restricted to Employees in India only
	#write_INDIA
	# Restricted to Employees in China only
	#write_CHINA
	#echo
	#echo "Promoting Network Manager VPN Profiles."
	#cp -f *.nmconnection /etc/NetworkManager/system-connections/ 
	#echo "Restarting Network Manager to pick up changes"
	#systemctl restart NetworkManager

	#Build Cisco Anyconnect
	echo ""
	echo "##################################################"
	read -p "Optional: Additional Cert Setup for Cisco Anyconnect VPN Usage [Y/N]: " validate
	echo ""
	rc=$(echo "${validate}"| grep -qi "^y")
	if [[ $? -eq 0 ]]; then 
		echo "##################################################"
		echo "Setting up VPN for Cisco Anyconnect"
		su - ${username} -c "mkdir -p ${_HOME}/.cisco/certificates/client/private/"
		openssl pkcs12 -nokeys -clcerts -in "${file_name}" -out ${_HOME}/.cisco/certificates/client/${username}.pem -passin pass:"$password"
		check $?
		openssl pkcs12 -nocerts -nodes -in "${file_name}" -out ${_HOME}/.cisco/certificates/client/private/${username}.key -passin pass:"$password" -passout pass:"$password"
		check $?
		chown -f ${username}.${username} ${_HOME}/.cisco/certificates/client/${username}.pem ${_HOME}/.cisco/certificates/client/private/${username}.key
		chmod 600 ${_HOME}/.cisco/certificates/client/${username}.pem ${_HOME}/.cisco/certificates/client/private/${username}.key
		if [[ $? -eq 0 ]]; then
			echo "					  Success."
		else
			echo "Cert Error: Most likely a password issue with your certificate."
		fi
	fi
	cd ${currdir}
}

function enable_openclient_repo {
	# Enable Openclient repo
	perl -pi -e 's/enabled=0/enabled=1/g' /etc/yum.repos.d/openclient.repo
	# Disable Openclient GSA repo
	perl -pi -e 's/enabled=1/enabled=0/g' /etc/yum.repos.d/openclient-gsa.repo
}


function write_vpn_region {
	All=10
	None=11
	clear_all_picks
	GEO=$(grep Geography /var/opt/ibmsam/registry.ini | cut -d'=' -f 2 | sed 's/ //g')
	case "${GEO}" in
		"US"|"LA"|"Canada")
			pick 1
			pick 2
			pick 3
			;;
		"EMEA")
			pick 4
			pick 5
			;;
		"AP")
			pick 6
			pick 7
			pick 8
			pick 9
			;;
		*)
			pick ${None}
			;;
	esac
		
	PS3=$'\n'"Please check all of the VPN Regions you would like to setup."$'\n'"You may check multiple items, or alternatively, just leave your Default Regions."$'\n'$'\n'"Select / Deselect one item at a time: "
	while true ; do
		clear
		echo "### IBM SAS VPN Regions: Select All that Apply ###"
		echo ""
		menu_item=(	"AMERICA-POK [${selected[1]}]"			\
				"AMERICA-RALEIGH [${selected[2]}]"		\
				"AMERICA-BOULDER [${selected[3]}]"		\
				"EUROPE-MEA [${selected[4]}]"			\
				"EUROPE-MEA-FAST [${selected[5]}]"			\
				"AP-ASEAN [${selected[6]}]"			\
				"JAPAN [${selected[7]}]"			\
				"CHINA [${selected[8]}]"			\
				"INDIA [${selected[9]}]"			\
				"All of the above [${selected[${All}]}]"	\
				"None of the above [${selected[${None}]}]"	\
				"Done")
		select opt in "${menu_item[@]}"; do
			case ${opt} in
				"AMERICA-POK [${selected[1]}]")
					pick 1
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"AMERICA-RALEIGH [${selected[2]}]")
					pick 2
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"AMERICA-BOULDER [${selected[3]}]")
					pick 3
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"EUROPE-MEA [${selected[4]}]")
					pick 4
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"EUROPE-MEA-FAST [${selected[5]}]")
					pick 5
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"AP-ASEAN [${selected[6]}]")
					pick 6
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"JAPAN [${selected[7]}]")
					pick 7
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"CHINA [${selected[8]}]")
					pick 8
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"INDIA [${selected[9]}]")
					pick 9
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"All of the above [${selected[${All}]}]" )
					select_all_picks ${None}
					clear_pick ${None}
					break
					;;
				"None of the above [${selected[${None}]}]" )
					clear_all_picks_except ${None}
					break
					;;
				"Done")
					break 2
					;;
				*)
					break
					;;
			esac
		done
	done
	for opt in "${!selected[@]}"; do
		if [[ ${selected[opt]} ]]; then
			if [ ${opt} -eq 1 ]; then write_AMERICA_POK; fi
			if [ ${opt} -eq 2 ]; then write_AMERICA_RALEIGH; fi
			if [ ${opt} -eq 3 ]; then write_AMERICA_BOULDER; fi
			if [ ${opt} -eq 4 ]; then write_EUROPE_MEA; fi
			if [ ${opt} -eq 5 ]; then write_EUROPE_MEA_FAST; fi
			if [ ${opt} -eq 6 ]; then write_AP_ASEAN; fi
			if [ ${opt} -eq 7 ]; then write_JAPAN; fi
			if [ ${opt} -eq 8 ]; then write_CHINA; fi
			if [ ${opt} -eq 9 ]; then write_INDIA; fi
		fi
	done
	echo ""
	cp -f *.nmconnection /etc/NetworkManager/system-connections/ 
	if [[ -f /usr/share/ibm-config-NetworkManager-openconnect/ohsd.py ]]; then
		rc=$(perl -pi -e 's/proxies = proxies/proxies = proxies, verify=False/g' /usr/share/ibm-config-NetworkManager-openconnect/ohsd.py 2>&1 >/dev/null)
	fi
	echo "Restarting Network Manager to pick up changes"
	systemctl restart NetworkManager
	echo ""
	echo "VPN Certs Stored in ${_DOCUMENTS}/IBM_SAS_VPN/"
	echo ""
	read -p "Selected VPN Profiles have been built - press Enter to Continue." inputs
}

# System Level Tweaks..it's easy to add more.
function menu_system_tweaks {
	All=10
	None=11
	clear_all_picks
	pick ${None}
	PS3=$'\n'"Please check all of System Tweaks you would like to apply."$'\n'"You may check multiple items, or alternatively, check \"None of the Above\""$'\n'$'\n'"Select / Deselect one item at a time: "
	while true ; do
		clear
		echo "### System Tweaks: Select All that Apply ###"
		echo ""
		menu_item=(	"Set SELinux to Disabled [${selected[1]}]"						\
				"Set SELinux to Permissive [${selected[2]}]"						\
				"Enable DNF Fastest Mirror [${selected[3]}]"					\
				"Enable IPV4 Forwarding for Virtual Machines [${selected[4]}]"			\
				"Enable Auto SSD Discards [${selected[5]}]"					\
				"Smaller Tabbed Menu in Terminal [${selected[6]}]"				\
				"Disable IPV6 System Wide (Grub) [${selected[7]}]"				\
				"Nicer Default VIM Colors and Syntax Highlighting [${selected[8]}]"		\
				"Unlimited and TimeStamped Bash History for root and user [${selected[9]}]"	\
				"All of the above [${selected[${All}]}]"					\
				"None of the above [${selected[${None}]}]"					\
				"Done")
		select opt in "${menu_item[@]}"; do
			case $opt in
				"Set SELinux to Disabled [${selected[1]}]")
					pick 1
					clear_pick 2
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"Set SELinux to Permissive [${selected[2]}]")
					pick 2
					clear_pick 1
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"Enable DNF Fastest Mirror [${selected[3]}]")
					pick 3
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"Enable IPV4 Forwarding for Virtual Machines [${selected[4]}]")
					pick 4
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"Enable Auto SSD Discards [${selected[5]}]")
					pick 5
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"Smaller Tabbed Menu in Terminal [${selected[6]}]")
					pick 6
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"Disable IPV6 System Wide (Grub) [${selected[7]}]")
					pick 7
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"Nicer Default VIM Colors and Syntax Highlighting [${selected[8]}]")
					pick 8
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"Unlimited and TimeStamped Bash History for root and user [${selected[9]}]")
					pick 9
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"All of the above [${selected[${All}]}]" )
					select_all_picks ${None}
					clear_pick 2
					clear_pick ${None}
					break
					;;
				"None of the above [${selected[${None}]}]" )
					clear_all_picks_except ${None}
					break
					;;
				"Done")
					break 2
					;;
				*)
					break
					;;
			esac
		done
	done
	for opt in "${!selected[@]}"; do
		if [[ ${selected[opt]} ]]; then
			if [ ${opt} -eq 1 ]; then disable_selinux; fi
			if [ ${opt} -eq 2 ]; then permissive_selinux; fi
			if [ ${opt} -eq 3 ]; then dnf_fastest_mirror; fi
			if [ ${opt} -eq 4 ]; then ipv4_forwarding; fi
			if [ ${opt} -eq 5 ]; then enable_discards_lvm; ssd_tweaks_fstab; ssd_elevator_grub; fi
			if [ ${opt} -eq 6 ]; then terminal_gtk_tweaks; fi
			if [ ${opt} -eq 7 ]; then ipv6_disable_grub; fi
			if [ ${opt} -eq 8 ]; then vimrc_root; vimrc_user; fi
			if [ ${opt} -eq 9 ]; then bash_history_root; bash_history_user; fi
			sleep 1 # so we can watch output
		fi
	done
	update_dracut_grub
	echo ""
	read -p "System Tweaks are Complete - press Enter to Continue." inputs
}

# Google Chrome
function menu_google_chrome {
	None=4
	clear_all_picks
	pick ${None}
	PS3=$'\n'"Select whichever Chrome versions you would like to Install."$'\n'"This step will install the google-chrome repository for easy updates with dnf"$'\n'$'\n'"Select / Deselect one item at a time: "
	while true ; do
		clear
		echo "### Chrome Browser: Select All that Apply ###"
		echo ""
		menu_item=(	"Google Chrome Repo and (Stable) Browser [${selected[1]}]"	\
				"Google Chrome Repo and (Beta) Browser [${selected[2]}]"	\
				"Google Chrome Repo and (Unstable) Browser [${selected[3]}]"	\
				"None of the above [${selected[${None}]}]"			\
				"Done")
		select chrome_opt in "${menu_item[@]}"; do
			case $chrome_opt in
				"Google Chrome Repo and (Stable) Browser [${selected[1]}]")
					pick 1
					clear_pick ${None}
					break
					;;
				"Google Chrome Repo and (Beta) Browser [${selected[2]}]")
					# Beta or unstable, but not both..theres a bad dep issue
					pick 2
					clear_pick 3
					clear_pick ${None}
					break
					;;
				"Google Chrome Repo and (Unstable) Browser [${selected[3]}]")
					# Beta or unstable, but not both..theres a bad dep issue
					pick 3
					clear_pick 2
					clear_pick ${None}
					break
					;;
				"None of the above [${selected[${None}]}]" )
					clear_all_picks_except ${None}
					break
					;;
				"Done")
					break 2
					;;
				*)
					break
					;;
			esac
		done
	done
	for chrome_opt in "${!selected[@]}"; do
		if [[ ${selected[chrome_opt]} ]]; then
			if [ ${chrome_opt} -eq 1 ]; then install_google_chrome_repository; install_google_chrome_stable; fi
			if [ ${chrome_opt} -eq 2 ]; then install_google_chrome_repository; install_google_chrome_beta; fi
			if [ ${chrome_opt} -eq 3 ]; then install_google_chrome_repository; install_google_chrome_unstable; fi
			sleep 1 # so we can watch output
		fi
	done
	echo ""
	read -p "Google Chrome setup Complete - press Enter to Continue." inputs
}

function package_installs {
	All=13
	None=14
	clear_all_picks
	pick ${None}
	PS3=$'\n'"Select Any/All/None packages you would like to Install."$'\n'"This step may trigger additional menus."$'\n'$'\n'"Select / Deselect one item at a time: "
	while true ; do
		clear
		echo "### Package Installs: Select All that Apply ###"
		echo ""
		menu_item=(	"RPM Fusion Free [${selected[1]}]"						\
				"RPM Fusion Non-Free [${selected[2]}]"						\
				"MS True Type Fonts (msttcore) SourceForge (EXPERIMENTAL can take 20 mins) [${selected[3]}]" \
				"Utils: pavucontrol gparted fwupd flameshot screen [${selected[4]}]"		\
				"KVM / QEMU Virtualization [${selected[5]}]"					\
				"SAMBA Shares / SMB Config for Virtualization [${selected[6]}]"			\
				"RPM Development Tools [${selected[7]}]"					\
				"NVIDIA Negativo17 Driver (SubMenu) [${selected[8]}]"				\
				"Google Chrome Repo and choice of Browser (SubMenu) [${selected[9]}]"		\
				"Vim [${selected[10]}]"								\
				"Emacs [${selected[11]}]"							\
				"Libreoffice [${selected[12]}]"							\
				"All of the above [${selected[${All}]}]"					\
				"None of the above [${selected[${None}]}]"					\
				"Done")
		select opt in "${menu_item[@]}"; do
			case $opt in
				"RPM Fusion Free [${selected[1]}]")
					pick 1
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"RPM Fusion Non-Free [${selected[2]}]")
					pick 2
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"MS True Type Fonts (msttcore) SourceForge (EXPERIMENTAL can take 20 mins) [${selected[3]}]")
					pick 3
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"Utils: pavucontrol gparted fwupd flameshot screen [${selected[4]}]")
					pick 4
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"KVM / QEMU Virtualization [${selected[5]}]")
					pick 5
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"SAMBA Shares / SMB Config for Virtualization [${selected[6]}]")
					pick 6
					if [[ ${selected[6]} == '+' ]]; then
						selected[5]='+'
					fi
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"RPM Development Tools [${selected[7]}]")
					pick 7
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"NVIDIA Negativo17 Driver (SubMenu) [${selected[8]}]")
					pick 8
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"Google Chrome Repo and choice of Browser (SubMenu) [${selected[9]}]")
					pick 9
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"Vim [${selected[10]}]")
					pick 10
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"Emacs [${selected[11]}]")
					pick 11
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"Libreoffice [${selected[12]}]")
					pick 12
					clear_pick ${None}
					clear_pick ${All}
					break
					;;
				"All of the above [${selected[${All}]}]" )
					select_all_picks ${None}
					# Dont take EXPERIMENTAL items
					clear_pick 3
					clear_pick ${None}
					break
					;;
				"None of the above [${selected[${None}]}]" )
					clear_all_picks_except ${None}
					break
					;;
				"Done")
					break 2
					;;
				*)
					break
					;;
			esac
		done
	done
	for opt in "${!selected[@]}"; do
		if [[ ${selected[opt]} ]]; then
			if [ ${opt} -eq 1 ]; then install_rpm_fusion_free; fi
			if [ ${opt} -eq 2 ]; then install_rpm_fusion_nonfree; fi
			# MS TT Core Fonts installer can hang during download..so lets disable it for now
			if [ ${opt} -eq 3 ]; then install_msttcore_fonts; fi
			if [ ${opt} -eq 4 ]; then install_system_utils; fi
			if [ ${opt} -eq 5 ]; then 
				group_install_virtualization
				install_virtualization_utils
			fi
			if [ ${opt} -eq 6 ]; then 
				if [ "${selected[5]}" == "" ]; then
					# Pre reqs
					group_install_virtualization
					install_virtualization_utils
				fi
				install_samba
				setup_samba_config
				firewall_rules_samba_libvirt
				# there's less WST issues for the VPN if we dont start samba
				# if the user wants it, they will install a Win10 VM and turn it on
				#enabling_samba
				#starting_samba
				generate_samba_account
			fi
			if [ ${opt} -eq 7 ]; then
				install_rpm_utilities
				group_install_c_development_tools
				group_install_development_tools
			fi
			if [ ${opt} -eq 8 ]; then DO_NVIDIA="true"; fi
			if [ ${opt} -eq 9 ]; then DO_CHROME="true"; fi
			if [ ${opt} -eq 10 ]; then install_vim; fi
			if [ ${opt} -eq 11 ]; then install_emacs; fi
			if [ ${opt} -eq 12 ]; then install_libreoffice; fi
			sleep 1 # so we can watch output
		fi
	done
}

function menu_package_installs {
	package_installs
	if [ "${DO_NVIDIA}" == "true" ]; then
		menu_nvidia
	fi

	if [ "${DO_CHROME}" == "true" ]; then
		menu_google_chrome
	fi
	echo ""
	read -p "Package Installs Complete - press Enter to Continue." inputs
}

function menu_nvidia {
	None=5
	clear_all_picks
	pick ${None}
	PS3=$'\n'"Select 1 of the NVIDIA Drivers you would like to Install."$'\n'"This step will install the appropriate repository for easy updates with dnf"$'\n'$'\n'"Select / Deselect one item at a time: "
	while true ; do
		clear
		echo "### Negativo17 NVIDIA Driver: Select ONE ###"
		echo ""
		menu_item=(	"NVIDIA Driver / AKMODS [${selected[1]}]"			\
				"NVIDIA Driver / DKMS [${selected[2]}]"				\
				"NVIDIA Driver / MultiMedia Repo / AKMODS [${selected[3]}]"	\
				"NVIDIA Driver / MultiMedia Repo / DKMS [${selected[4]}]"	\
				"None of the above [${selected[${None}]}]"			\
				"Done")
		select nvidia_opt in "${menu_item[@]}"; do
			case $nvidia_opt in
				"NVIDIA Driver / AKMODS [${selected[1]}]")
					clear_all_picks 
					pick 1
					break
					;;
				"NVIDIA Driver / DKMS [${selected[2]}]")
					clear_all_picks
					pick 2
					break
					;;
				"NVIDIA Driver / MultiMedia Repo / AKMODS [${selected[3]}]")
					clear_all_picks
					pick 3
					break
					;;
				"NVIDIA Driver / MultiMedia Repo / DKMS [${selected[4]}]" )
					clear_all_picks
					pick 4
					break
					;;
				"None of the above [${selected[${None}]}]" )
					clear_all_picks_except ${None}
					break
					;;
				"Done")
					break 2
					;;
				*) 
					break 
					;;
			esac
		done
	done
	for nvidia_opt in "${!selected[@]}"; do
		if [[ ${selected[nvidia_opt]} ]]; then
			if [ ${nvidia_opt} -eq 1 ]; then
				NVIDIA_REPO_TYPE=fedora-nvidia
				NVIDIA_KMOD_TYPE=akmod-nvidia
				check_nvidia_and_install
			fi
			if [ ${nvidia_opt} -eq 2 ]; then
				NVIDIA_REPO_TYPE=fedora-nvidia
				NVIDIA_KMOD_TYPE=dkms-nvidia
				check_nvidia_and_install
			fi
			if [ ${nvidia_opt} -eq 3 ]; then
				NVIDIA_REPO_TYPE=fedora-multimedia
				NVIDIA_KMOD_TYPE=akmod-nvidia
				check_nvidia_and_install
			fi
			if [ ${nvidia_opt} -eq 4 ]; then
				NVIDIA_REPO_TYPE=fedora-multimedia
				NVIDIA_KMOD_TYPE=dkms-nvidia
				check_nvidia_and_install
			fi
			sleep 1 # so we can watch output
		fi
	done
	echo ""
	read -p "Negativo17 NVIDIA Driver setup Complete - press Enter to Continue." inputs
}
# OC FEDORA MENU
function menu_optional_ocfedora {
	None=8
	clear_all_picks
	pick ${None}
	PS3=$'\n'"Optional Install Packages(This list will grow)."$'\n'$'\n'"Select / Deselect one item at a time: "
	while true ; do
		clear
		echo "### Optional Packages: Select All that Apply ###"
		echo ""
		menu_item=(	"Install IBM Notes (ocfedora Repo) [${selected[1]}]"				\
				"Slack 4.3.2 (ocfedora Repo) [${selected[2]}]"					\
				"Slack 4.4.2 (slacktechnologies Repo) [${selected[3]}]"				\
				"Skype (skypeforlinux from the Skype-Stable Repo) [${selected[4]}]"		\
				"Microsoft Teams (teams Repo) [${selected[5]}]"					\
				"Microsoft Visual Studio Code (vscode Repo) [${selected[6]}]"			\
				"Atom Editor (atom Repo) [${selected[7]}]"			\
				"None of the above [${selected[${None}]}]"					\
				"Done")
		select opt in "${menu_item[@]}"; do
			case $opt in
				"Install IBM Notes (ocfedora Repo) [${selected[1]}]")
					pick 1
					clear_pick ${None}
					break
					;;
				"Slack 4.3.2 (ocfedora Repo) [${selected[2]}]")
					pick 2
					clear_pick 3
					clear_pick ${None}
					break
					;;
				"Slack 4.4.2 (slacktechnologies Repo) [${selected[3]}]")
					pick 3
					clear_pick 2
					clear_pick ${None}
					break
					;;
				"Skype (skypeforlinux from the Skype-Stable Repo) [${selected[4]}]")
					pick 4
					clear_pick ${None}
					break
					;;
				"Microsoft Teams (teams Repo) [${selected[5]}]")
					pick 5
					clear_pick ${None}
					break
					;;
				"Microsoft Visual Studio Code (vscode Repo) [${selected[6]}]")
					pick 6
					clear_pick ${None}
					break
					;;
				"Atom Editor (atom Repo) [${selected[7]}]")
					pick 7
					clear_pick ${None}
					break
					;;
				"None of the above [${selected[${None}]}]" )
					clear_all_picks_except ${None}
					break
					;;
				"Done")
					break 2
					;;
				*)
					break
					;;
			esac
		done
	done
	for opt in "${!selected[@]}"; do
		if [[ ${selected[opt]} ]]; then
			if [ ${opt} -eq 1 ]; then group_install_ibm_notes; fi 
			if [ ${opt} -eq 2 ]; then install_slack; fi
			if [ ${opt} -eq 3 ]; then install_slack_repository; install_slack; fi
			if [ ${opt} -eq 4 ]; then install_skype_repository; install_skype; fi
			if [ ${opt} -eq 5 ]; then install_msft_teams_repository; install_msft_teams; fi
			if [ ${opt} -eq 6 ]; then install_msft_visual_studio_code_repository; install_msft_visual_studio_code; fi
			if [ ${opt} -eq 7 ]; then install_atom_editor_repository; install_atom_editor; fi
			sleep 1 # so we can watch output
		fi
	done
	echo ""
	read -p "Optional Package Install Complete - press Enter to Continue." inputs
}

function enable_openclient_repository {
	if [[ "${ALREADY_CONNECTED}" == "false" ]]; then
		TMP_OPTIONS="${DNF_OPTIONS}"
		DNF_OPTIONS="${TMP_OPTIONS} --enablerepo=openclient-gsa"
	else
		echo "##################################################"
		echo "Installing openclient-release"
		list=$(curl -s http://ocfedora.hursley.ibm.com/fedora/${FEDORA_VERSION}/x86_64/ | sed 's/<[^>]*>/ /g' | grep "openclient-release" | awk '{print $1}' | sort | tail -1)
		TMP_OPTIONS="${DNF_OPTIONS}"
		DNF_OPTIONS="${TMP_OPTIONS} --nogpgcheck"
		install_list "http://ocfedora.hursley.ibm.com/fedora/${FEDORA_VERSION}/x86_64/${list}" "openclient-release already Installed -   Skipping."
		DNF_OPTIONS="${TMP_OPTIONS}"
	fi
}

function disable_openclient_gsa_repository {
	if [[ "${ALREADY_CONNECTED}" == "false" ]]; then
		DNF_OPTIONS="${TMP_OPTIONS}"
	fi
}

function stage_2_do_vpn {
	if [ -f /root/.vpn-registered ]; then
		setup_vpn
		#enable_openclient_repo
		echo ""
		echo "Now that your VPN is set up, Please try connecting to the IBM VPN."
		echo ""
		echo "After connecting, you will need to Run ISAM to fully register this system."
		echo ""
		echo "Then install ibm-dnf-plugins ( sudo dnf install ibm-dnf-plugins ),"
		echo "in order to enable access to IBM Restricted Repositories."
		echo ""
		echo "Then you will have access to install EC Print, Crashplan and other"
		echo "internal IBM software which was not available on the W3 GettingStarted VPN."
		exit 0
	fi
}

function ibmify {
	echo ""
	echo "##################################################"
	echo "IBM OC Fedora Base Layer is about to be Installed."
	read -p "Press Enter to Continue." inputs
	fix_accounts
	remove_junk_rpms
	install_unresolved_deps
	install_fedora_openclient_gsa_repository
	enable_openclient_repository
	group_install_ibm_client_base
	disable_openclient
	#disable_openclient_repo
	echo "##################################################"
	echo "IBM OC Fedora Base Layer Install Complete."
	echo ""
	echo "IBM OC Fedora Required Security Packages are about to be Installed."
	read -p "Press Enter to Continue." inputs
	#group_install_ibm_workstation_security_tool
	#group_install_ibm_security_compliance
	#group_install_ibm_firewall_rules
	#group_install_ibm_openconnect
	group_install_ibm_vpn
	read -p "IBM OC Fedora Required Packages Installed - Press Enter to Continue." inputs
	menu_optional_ocfedora
	#run_ibmregtool
	run_ibmregtool_cmd
	register_sas_vpn
	wait_for_registration
	#disable_openclient_gsa_repository
}

### Main ###
clear

# Are we running as root?
root_check

# OC Fedora Intro
intro

# check for /root/.vpn-registered
stage_2_do_vpn

# Pre-flight sanity checks
initialize

### Get connected to the W3 Getting Started VPN if needed
ibm_w3_vpn

### System wide Upgrade to ensure we are current and reboot if needed
dnf_upgrade
get_rpm_list
get_groups_list

# Menu for System Tweaks
menu_system_tweaks

# Menu for Package Installs
menu_package_installs

# IBM-ification
ibmify

# Done print out some info to the user
finalize

#enabling_ssh
#starting_ssh
#rpmconf -a

