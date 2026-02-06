#!/bin/bash
#
# https://github.com/Nyr/openvpn-install
# Modified to support OpenCloudOS
#
# Copyright (c) 2013 Nyr. Released under the MIT License.

if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".'
	exit
fi

read -N 999999 -t 0.001

# Detect OS
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	group_name="nogroup"
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
	group_name="nobody"
elif [[ -e /etc/os-release ]] && grep -qi 'opencloudos' /etc/os-release; then
	os="centos"
	# Robust version extraction for OpenCloudOS
	os_version=$(grep "^VERSION_ID=" /etc/os-release | sed -E 's/.*="?([0-9]+).*/\1/')
	group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	group_name="nobody"
else
	echo "This installer seems to be running on an unsupported distribution."
	echo "Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS, Fedora and OpenCloudOS."
	exit 1
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
	echo "Ubuntu 22.04 or higher is required."
	exit 1
fi

if [[ "$os" == "debian" ]]; then
	if grep -q '/sid' /etc/debian_version; then
		echo "Debian Testing/Unstable unsupported."
		exit 1
	fi
	if [[ "$os_version" -lt 11 ]]; then
		echo "Debian 11 or higher required."
		exit 1
	fi
fi

if [[ "$os" == "centos" && "$os_version" -lt 9 ]]; then
	echo "OpenCloudOS/CentOS/Rocky/AlmaLinux 9 or higher is required."
	echo "This version ($os_version) is too old."
	exit 1
fi

if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try "su -" instead of "su".'
	exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "Run with superuser privileges."
	exit 1
fi

if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
	echo "TUN device not available. Enable TUN before installing."
	exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -e /etc/openvpn/server/server.conf ]]; then
	clear
	echo 'Welcome to OpenVPN road warrior installer!'

	# IPv4 selection
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		echo; echo "Which IPv4 address should be used?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4 address [1]: " ip_number
		[[ -z "$ip_number" ]] && ip_number=1
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "${ip_number}p")
	fi

	# NAT detection
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo; echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		get_public_ip=$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")
		get_public_ip=$(grep -m1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$get_public_ip")
		read -p "Public IPv4 / hostname [$get_public_ip]: " public_ip
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi

	# Protocol
	echo; echo "Which protocol should OpenVPN use?"
	echo "   1) UDP (recommended)"
	echo "   2) TCP"
	read -p "Protocol [1]: " protocol
	case "$protocol" in
		1|"") protocol=udp ;;
		2)    protocol=tcp ;;
		*)    echo "Invalid"; exit 1 ;;
	esac

	# Port
	read -p "Port [1194]: " port
	[[ -z "$port" ]] && port=1194

	# DNS
	echo; echo "Select a DNS server for clients:"
	echo "   1) System default"
	echo "   2) Google"
	echo "   3) 1.1.1.1"
	echo "   4) OpenDNS"
	echo "   5) Quad9"
	read -p "DNS [1]: " dns
	[[ -z "$dns" ]] && dns=1

	# Client name
	read -p "Client name [client]: " unsanitized_client
	client=$(sed 's/[^a-zA-Z0-9_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="client"

	echo; echo "Installing OpenVPN..."

	# Install packages
	dnf install -y epel-release
	dnf install -y openvpn openssl ca-certificates iptables firewalld

	# EasyRSA
	mkdir -p /etc/openvpn/server/easy-rsa/
	curl -sL https://github.com/OpenVPN/easy-rsa/releases/download/v3.2.5/EasyRSA-3.2.5.tgz | tar xz -C /etc/openvpn/server/easy-rsa/ --strip-components=1

	cd /etc/openvpn/server/easy-rsa/
	./easyrsa --batch init-pki
	./easyrsa --batch build-ca nopass
	./easyrsa gen-tls-crypt-key

	cat > /etc/openvpn/server/dh.pem << DH_EOF
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
DH_EOF

	./easyrsa --batch build-server-full server nopass
	./easyrsa --batch build-client-full "$client" nopass
	./easyrsa --batch gen-crl

	cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn/server/
	cp pki/private/easyrsa-tls.key /etc/openvpn/server/tc.key
	chown nobody:nobody /etc/openvpn/server/crl.pem
	chmod o+x /etc/openvpn/server/

	# Server config
	cat > /etc/openvpn/server/server.conf << SERVER_EOF
local $ip
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
ifconfig-pool-persist ipp.txt
keepalive 10 120
user nobody
group nobody
persist-key
persist-tun
verb 3
crl-verify crl.pem
explicit-exit-notify
SERVER_EOF

	# DNS options
	case "$dns" in
		2) echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server/server.conf
		   echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server/server.conf ;;
		3) echo 'push "dhcp-option DNS 1.1.1.1"' >> /etc/openvpn/server/server.conf
		   echo 'push "dhcp-option DNS 1.0.0.1"' >> /etc/openvpn/server/server.conf ;;
		4) echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/server/server.conf
		   echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/server/server.conf ;;
		5) echo 'push "dhcp-option DNS 9.9.9.9"' >> /etc/openvpn/server/server.conf
		   echo 'push "dhcp-option DNS 149.112.112.112"' >> /etc/openvpn/server/server.conf ;;
	esac

	# Enable IP forwarding
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-openvpn.conf
	sysctl -p /etc/sysctl.d/30-openvpn.conf

	# Firewall
	systemctl enable --now firewalld
	firewall-cmd --permanent --add-port=$port/$protocol
	firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
	firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $ip
	firewall-cmd --reload

	# Client template
	public_ip=${public_ip:-$ip}
	cat > /etc/openvpn/server/client-common.txt << CLIENT_EOF
client
dev tun
proto $protocol
remote $public_ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
verb 3
CLIENT_EOF

	# Generate .ovpn
	grep -v '^#' /etc/openvpn/server/client-common.txt > /root/${client}.ovpn
	cat /etc/openvpn/server/ca.crt | sed -e '1i\<ca>' -e '$a\</ca>' >> /root/${client}.ovpn
	cat /etc/openvpn/server/ta.key | sed -e '1i\<tls-auth>' -e '$a\</tls-auth>' >> /root/${client}.ovpn
	cat /etc/openvpn/server/pki/private/${client}.key | sed -e '1i\<key>' -e '$a\</key>' >> /root/${client}.ovpn
	cat /etc/openvpn/server/pki/issued/${client}.crt | sed -e '1i\<cert>' -e '$a\</cert>' >> /root/${client}.ovpn

	systemctl enable --now openvpn-server@server.service

	echo
	echo "✅ OpenVPN installed successfully!"
	echo "📁 Client config: /root/${client}.ovpn"
	echo "📤 Transfer this file to your device to connect."
else
	clear
	echo "OpenVPN is already installed."
	echo
	echo "Select an option:"
	echo "   1) Add a new client"
	echo "   2) Revoke an existing client"
	echo "   3) Remove OpenVPN"
	echo "   4) Exit"
	read -p "Option: " option
	case "$option" in
		1)
			echo; read -p "Client name: " unsanitized_client
			client=$(sed 's/[^a-zA-Z0-9_-]/_/g' <<< "$unsanitized_client")
			cd /etc/openvpn/server/easy-rsa/
			./easyrsa --batch build-client-full "$client" nopass
			grep -v '^#' /etc/openvpn/server/client-common.txt > "/root/${client}.ovpn"
			cat /etc/openvpn/server/ca.crt | sed -e '1i\<ca>' -e '$a\</ca>' >> "/root/${client}.ovpn"
			cat /etc/openvpn/server/ta.key | sed -e '1i\<tls-auth>' -e '$a\</tls-auth>' >> "/root/${client}.ovpn"
			cat /etc/openvpn/server/pki/private/${client}.key | sed -e '1i\<key>' -e '$a\</key>' >> "/root/${client}.ovpn"
			cat /etc/openvpn/server/pki/issued/${client}.crt | sed -e '1i\<cert>' -e '$a\</cert>' >> "/root/${client}.ovpn"
			echo; echo "✅ Client ${client} added. Config: /root/${client}.ovpn"
			;;
		2)
			echo "Revocation not implemented in this minimal version."
			;;
		3)
			echo "Removal not implemented. Please remove manually."
			;;
		*)
			echo "Bye!"
			;;
	esac
fi
EOF
