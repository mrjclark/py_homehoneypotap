#!/bin/bash

trap 'log_event "ERROR: Script failed at line $LINENO"' ERR

SIEM_USR=siem
LOG_FILE=/var/log/homehoneypot/honeypot_set.log
SIEM_FOLDER=/usr/siem


log_event() {
	echo "$(date -Iseconds) | $1" >> $LOG_FILE
}

log_fail() {
	log_event $1
	exit 1
}


touch $LOG_FILE
log_event "Ensure log file exists"

log_event "Creating SIEM user"
sudo adduser $SIEM_USR --disabled-password --gecos "" || log_fail "ERROR: Failed to create $(SIEM_USR)"

log_event "Update repository index and install hostapd and dnsmasq"
sudo apt update && sudo apt hostapd dnsmasq -y >> $LOG_FILE || log_fail "ERROR: Could not update repository index or install hostapd and dnsmasq"

log_event "Create hostapd.conf file"
echo ("#Change wlan0 to the wireless device\ninterface=wlan0\ndriver nl80211\n=HomeOpen\nchannel=6") >> ~/hostapd.conf

log_event "Uncomment dhcp_server line in dnsmasq.conf"
CONFIG_FILE=/etc/dnsmasq.conf
sed -i '/^.*dhcp-range/s/^#//' /etc/dnsmasq.conf || log_fail "ERROR: Failed to uncomment dhcp-range in dnsmasq.conf" 

log_event "Enable hostapd and dnsmasq"
systemctl unmask hostapd || log_fail "ERROR: Failed to unmask hostapd"
system enable hostapd || log_fail "ERROR: Failed to enable hostapd"
systemctl start hostapd || log_fail "ERROR: Failed to start hostapd"

log_event "Create event log for SIEM consumption"
mkdir $SIEM_FOLDER || log_fail "ERROR: could not create SIEM folder"
touch $SIEM_FOLDER/honeypot_events.log || log_fail "ERROR: Could not create SIEM log file"


log_event "Starting secure token creation and rotation"
log_event "Create environment variable secure file"

touch $SIEM_FOLDER/.env
echo "API_TOKEN=" > $SIEM_FOLDER/.env

touch $SIEM_FOLDER/bin/rotate_token.sh

