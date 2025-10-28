#!/bin/bash

trap 'log_event "ERROR: Script failed at line $LINENO"' ERR

RPI_SUSR="matthew"
HONEYPOT_LOG_FOLDER="/usr/var/log/homehoneyport/"
LOG_FILE="$HONEYPOT_LOG_FOLDER/honeypot_setup.log"
CONFIG_FILE="/etc/dnsmasq.conf"
TOKEN_ROTATE="/usr/bin/rotate_token.sh"
GET_EVENTS="/usr/bin/get_events.sh"
SIEM_USR="siem"
SIEM_FOLDER="/home/siem/"
TOKEN_FILE="$SIEM_FOLDER/.env"
HOSTAPD_LOG_FILE="$SIEM_FOLDER/var/log/hostapd.log"
DNSMASQ_LOG_FILE="$SIEM_FOLDER/var/log/dnsmasq.log"
PYTHON_FOLDER="~/py/"

log_event() {
	echo "$(date -Iseconds) | $1" >> $LOG_FILE
}

log_fail() {
	log_event "ERROR: $1"
	exit 1
}


mkdir -p $HONEYPOT_LOG_FOLDER
touch $LOG_FILE || log_fail "Could not create setup log file"
log_event "Ensure log file exists"

log_event "Creating SIEM user"
sudo adduser $SIEM_USR --disabled-password --gecos "" || log_fail "Failed to create user ${SIEM_USR}"

log_event "Update repository index and install package"
sudo apt update && sudo apt install hostapd dnsmasq openssl cron python3 nginx certbot python3-certbot-nginx -y >> $LOG_FILE || log_fail "Could not update repository index or install packages"


log_event "Create hostapd.conf file"
cat <<EOF > ~/hostapd.conf 
# Change wlan0 to the wireless device
interface=wlan0
driver=nl80211
ssid=HomeOpen
channel=6
EOF

log_event "Uncomment dhcp_server line in dnsmasq.conf"
sed -i '/^.*dhcp-range/s/^#//' /etc/dnsmasq.conf || log_fail "Failed to uncomment dhcp-range in dnsmasq.conf" 

log_event "Enable hostapd and dnsmasq"
systemctl unmask hostapd || log_fail "Failed to unmask hostapd"
systemctl enable hostapd || log_fail "Failed to enable hostapd"
systemctl start hostapd || log_fail "Failed to start hostapd"

log_event "Create event log for SIEM consumption"
mkdir $SIEM_FOLDER || log_fail "could not create SIEM folder"
touch $SIEM_FOLDER/honeypot_events.log || log_fail "Could not create SIEM log file"

log_event "Starting secure token creation and rotation"
log_event "Create environment variable secure file"

touch $TOKEN_FILE || log_fail "Could not create the environment variable file"
chown $RPI_SUSR:$SIEM_USR "$TOKEN_FILE"
chmod 640 "$TOKEN_FILE"
echo "API_TOKEN=" > $TOKEN_FILE || log_fail "Could not update the envinment variable file"

log_event "Create token rotation script"
touch $TOKEN_ROTATE || log_fail "Could not create the token rotation script"
cat <<EOF > $TOKEN_ROTATE || log_fail "Could not update token rotation script"
#!/bin/bash

# Config
TOKEN_FILE="${TOKEN_FILE}"
TOKEN_LOG_FILE="/var/log/honeypot/token.log"

# Generate new token
NEW_TOKEN=\$(openssl rand -hex 32)

# Replace token file
echo "API_TOKEN=\$NEW_TOKEN" > "\$TOKEN_FILE"

# Log rotation
echo "\$(date -Iseconds) | New token generated: \${NEW_TOKEN:0:8}..." >> \$TOKEN_LOG_FILE

# Restart API service
# If this is needed, put this in
EOF

log_event "Set token rotation script to update tokens daily"
chmod +x "$TOKEN_ROTATE" || log_fail "Could not make token rotation script executable"

log_event "Create log update scripts to get new events"
touch $GET_EVENTS || log_fail "Could not create the get events script"
cat <<EOF > $GET_EVENTS || log_fail "Could not update the get events script"
#!/bin/bash

# Config
HOSTAPD_LOG_FILE="${SIEM_USR}"
DNSMASQ_LOG_FILE="${SIEM_USR}"
SYSLOG="/var/log/syslog"

# Get last timestamp from hostapd log
LASTTIMESTAMP=\$(tail -1 "\$HOSTAPD_LOG_FILE" | awk '{print \$1, \$2, \$3}')
LASTEPOCH=\$(date -d "\$LASTTIMESTAMP" +"%s")

# Filter syslog for newer hostapd events
awk -v last="\$LAST_EPOCH" '
{
  cmd = "date -d \"" \$1 " " \$2 " " \$3 "\" +\"%s\""
  cmd | getline log_time
  close(cmd)
  if (log_time > last && \$0 ~ /hostapd/) print
}
' "\$SYSLOG" >> "\$HOSTAPD_LOG_FILE"

# Get last timestamp from dnsmasq log
LASTTIMESTAMP=\$(tail -1 "\$DNSMASQ_LOG_FILE" | awk '{print \$1, \$2, \$3}')
LASTEPOCH=\$(date -d "\$LASTTIMESTAMP" +"%s")

# Filter syslog for newer dnsmasq events
awk -v last="\$LAST_EPOCH" '
{
  cmd = "date -d \"" \$1 " " \$2 " " \$3 "\" +\"%s\""
  cmd | getline log_time
  close(cmd)
  if (log_time > last && \$0 ~ /dnsmasq/) print
}
' "\$SYSLOG" >> "\$DNSMASQ_LOG_FILE"
EOF

chmod +x $GET_EVENTS

log_event "Start cron"
sudo systemctl enable --now cron || log_fail "Could not start cron engine"

CRON_JOB_1="0 3 * * * $TOKEN_ROTATE"
CRON_JOB_2="* * * * * $GET_EVENTS"

log_event "Adding token rotation to cron jobs if missing"
(crontab -l 2>/dev/null; echo "$CRON_JOB_1"; echo "$CRON_JOB_2") | crontab -

log_event "Create python folder"
mkdir -p $PYTHON_FOLDER || log_fail "Could not create python folder"

log_event "Add python script requirements"
pip install -r requirements.txt || log_fail "Could not install python requirements"

log_event "Setting up gunicorn server"


log_event "Finished setting up raspberry pi for home honey pot AP"

