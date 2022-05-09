#!/bin/bash
#@dexter

SECONDS=0
# Define ANSI color variables
C=$(printf '\033')
RED='\033[0;31m'
BOLD_RED='\033[1;31m'
YELLOW="${C}[1;33m"
DULL_YELLOW='\033[0;33m'
BLUE="${C}[1;34m"
LIGHT_MAGENTA="${C}[1;95m"
GREEN="${C}[1;32m"
LIGHT_CYAN="${C}[1;96m"
NC='\033[0m'
origIFS="${IFS}"
ITALIC="${C}[3m"

printf """
    ${BLUE}/---------------------------------------------------------------------------\\
    |                                ${LIGHT_MAGENTA}OSCP SCAN${BLUE}                                  |
    |---------------------------------------------------------------------------| 
    |         ${YELLOW} A lightweight script to scan machines. Made by Dexter  ${BLUE}          |
    |---------------------------------------------------------------------------|
    |                                 ${LIGHT_MAGENTA}GG EZZ! ${BLUE}                                  |
    \---------------------------------------------------------------------------/${NC}
"""
echo

#CHECK ROOT PRIVS
if [[ $(/usr/bin/id | grep -i '0(root)') ]]; then
  IAMROOT="1"
  printf "${BOLD_RED}You are root or Password-less root via sudo is enabled!${NC}"
else
  IAMROOT=""
  printf "${DULL_YELLOW}You are NOT root${NC}"
fi
echo

#Discover OS
os_check() {
	OS_ttl=$(ping -c 1 $1 | grep "64 bytes" | cut -d " " -f 6 | cut -d "=" -f 2)
	if ((OS_ttl >= 60 && OS_ttl <= 68)); then
		echo "LINUX-based"
	elif ((OS_ttl >= 124 && OS_ttl <= 132)); then
		echo "WINDOWS"
	fi
}

#Check HOST via regex
host_verify() {
	if ! expr "${1}" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null && ! expr "${1}" : '^\(\([[:alnum:]-]\{1,63\}\.\)*[[:alpha:]]\{2,6\}\)$' >/dev/null; then
		printf "${RED}\n"
		printf "${RED}Invalid IP or URL!\n"
		exit 1
	fi
}

#--------------------------MAIN SCANS--------------------------
if [ "$1" == "" ]; then
	echo
        printf "${RED}Positional arguments missing!${NC}\n"
        printf "\nUsage: ${GREEN}./$(basename $0) <TARGET-IP> <DIR-NAME>${NC}\n"
        printf "Hint: ${DULL_YELLOW}Not specifying a directory = Quick Scan, Directory name provided = Full Scan${NC}\n"
        exit 1

elif [ "$2" == "" ]; then 
	echo
	echo "No directory name provided! QUICK scan initiated. TCP Scan by-default with added UDP Scan only if root."
	printf "NOTE - ${RED}${ITALIC}Scans will not be saved!${NC}\n"
	HOST=$1
	# Ensure $HOST is an IP or a URL
	host_verify $HOST
	echo

	#Discover OS
	OS_found=$(os_check $HOST)
	echo
	printf "${YELLOW}[+] Discovered OS - ${LIGHT_CYAN}$OS_found ${DULL_YELLOW}(90%% accurate)${NC}\n"

	#SCANS
	printf "${YELLOW}[+] TCP Scanning...${NC}\n"
	nmap --top-ports 1000 --min-rate 5000 -Pn -T4 $HOST
	if [ $IAMROOT == 1 ]; then
		echo
		printf "${YELLOW}[+] UDP Scanning...${NC}\n"
		sudo nmap -sU --top-ports 50 --max-rate 500 -Pn -T4 $HOST
	fi

else
	HOST=$1
	DIR=$2
	OUTPUTDIR="$HOME/0machines/$DIR"	#CAN CHANGE
	echo
	echo "FULL scan initiated. TCP Scan by-default with added UDP Scan only if root."
	# Ensure $HOST is an IP or a URL
	host_verify $HOST
	#Create directory to save scans and define filename
	printf "NOTE - ${GREEN}${ITALIC}Scans will be saved at $OUTPUTDIR${NC}\n"
	if [ ! -d "$OUTPUTDIR" ];then
		mkdir -p $OUTPUTDIR
	fi
	filename=scan-$DIR.nmap
	filename2=vulns-$DIR.nmap
	rm -rf $OUTPUTDIR/$filename 2>/dev/null

	#Discover OS
	OS_found=$(os_check $HOST)
	echo
	printf "${YELLOW}[+] Discovered OS - ${LIGHT_CYAN}$OS_found ${DULL_YELLOW}(90%% accurate)${NC}\n"
	
	#SCANS
	echo
	printf "${YELLOW}[+] TCP Scanning...${NC}\n"
	nmap --top-ports 1000 --min-rate 5000 -Pn -T4 $HOST
	echo
	printf "${YELLOW}[+] Initiating Full Scan and saving output in $filename...${NC}\n"
	ports=$(nmap -p- -Pn --min-rate=100 $HOST | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) && nmap -p$ports -Pn -sC -sV $HOST 1>$OUTPUTDIR/$filename 2>/dev/null
	if [ $IAMROOT == 1 ]; then
		printf "${YELLOW}[+] Appending UDP Scan to output...${NC}\n"
		ports_udp=$(sudo nmap -sU --top-ports 100 -Pn --max-rate 500 -T4 $HOST | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//) && sudo nmap -p$ports_udp -Pn -sU --open $HOST 1>>$OUTPUTDIR/$filename 2>/dev/null
	fi
	
	##----Suggest scans/commands based on services and OS----
	echo
	printf "${YELLOW}[+] Dropping conclusions & suggestions...${NC}\n"
	echo
	if [ $OS_found == "LINUX-based" ]; then
		printf "${GREEN}---------------------Recons to begin with: LINUX---------------------\n"
        	printf "${NC}\n"
		if echo $ports | grep -q "21" ; then
	                printf "${NC}\n"
		        printf "${LIGHT_CYAN}[*] 21/ftp:${NC} ftp $HOST 21\n"
		        echo
	        fi
	        if echo ${ports} | grep -q "53" ; then
	                printf "${NC}\n"
		        printf "${LIGHT_CYAN}[*] 53/dns:${NC}\n"
                	printf "\n\t dig ANY @${HOST} [<DOMAIN>]	${DULL_YELLOW}#Any information${NC}"
                	printf "\n\t dig axfr @${HOST} [<DOMAIN>]	${DULL_YELLOW}#Try zone transfer${NC}"
		        echo
	        fi
	        if echo ${ports} | grep -q "139\|445" ; then
	                printf "${NC}\n"
		        printf "${LIGHT_CYAN}[*] 445/smb:${NC} Do check for SMB version exploits\!\n"
                	printf "\n\t smbmap -H ${HOST} "
                	printf "\n\t smbclient -N -L //${HOST}	${DULL_YELLOW}#Null authentication${NC}"
		        echo
	        fi	
	elif [ $OS_found == "WINDOWS" ]; then
		printf "${GREEN}---------------------Recons to begin with: WINDOWS---------------------\n"
        	printf "${NC}\n"
	        if echo ${ports} | grep -q "53" ; then
	                printf "${NC}\n"
		        printf "${LIGHT_CYAN}[*] 53/dns:${NC}\n"
                	printf "\n\t dig ANY @${HOST} [<DOMAIN>]	${DULL_YELLOW}#Any information${NC}"
                	printf "\n\t dig axfr @${HOST} [<DOMAIN>]	${DULL_YELLOW}#Try zone transfer${NC}"
		        echo
		fi
	        if echo ${ports} | grep -q "88\|464" ; then
	                printf "${NC}\n"
		        printf "${LIGHT_CYAN}[*] 88/kerberos:${NC} Possible Active Directory \n"
		        echo
	        fi
	        if echo ${ports} | grep -q "135" ; then
	                printf "${NC}\n"
		        printf "${LIGHT_CYAN}[*] 135/msrpc:${NC} rpcclient ${HOST} ${DULL_YELLOW}OR${NC} rpcdump.py @${HOST} | egrep 'MS-RPRN|MS-PAR'  ${DULL_YELLOW}(-->PrintNightmare)${NC}\n"
		        echo
	        fi
	        if echo ${ports} | grep -q "139\|445" ; then
	                printf "${NC}\n"
		        printf "${LIGHT_CYAN}[*] 445/smb:${NC} \n"
                	printf "\n\t smbmap -H ${HOST} [-u 'guest']"
                	printf "\n\t smbclient -N -L //${HOST} ${DULL_YELLOW}OR${NC} smbclient -N \\\\\\\\\\\\\\\\${HOST}\\\\\\<SHARE>	${DULL_YELLOW}#Null authentication${NC}"
		        echo
	        fi
	        if echo ${ports} | grep -q "389\|636\|3268\|3269" ; then
	                printf "${NC}\n"
		        printf "${LIGHT_CYAN}[*] 389/ldap:${NC}\n"
                	printf "\n\t ldapsearch -x -h ${HOST} -s base namingcontexts [ -b \"DC=<1_SUBDOMAIN>,DC=<TDL>\" ]"
                	printf "\n\t ldapdomaindump ${HOST} --no-grep --no-html [ -u 'username' -p 'password' ]"
		        echo
      		fi
       	        if echo ${ports_udp} | grep -q "161\|162" ; then
	                printf "${NC}\n"
		        printf "${LIGHT_CYAN}[*] 161/snmp:${NC} snmpwalk -c public -v1 ${HOST}\n"
		        echo 
	        fi
	fi
	if echo ${ports} | grep -q "80\|443" ; then
                printf "${NC}\n"
	        printf "${LIGHT_CYAN}[*] HTTP/S WebServer found:${NC} (Do check for http service on other ports like 8080\!\n"
        	printf "\n\t whatweb ${HOST}"
        	printf "\n\t dirsearch -u http[s]://${HOST}/ -r 2 -t 50	${DULL_YELLOW}#Further, check with larger wordlists like seclists-raft${NC}"
        	printf "\n\t gobuster dns -d xor.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50"
        	printf "\n\t Try finding the CMS --> Example: Wordpress? > wpscan + exploits"
	        echo
        fi
	
	#Domain/Hostname Discovery
	domain_found=$(nmap -Pn -T4 -sV -p389 $HOST | grep "389/tcp" | cut -d " " -f 14 | tr -d ",")
	if [ -z $domain_found ]; then
		domain_found=$(nmap -Pn -T4 --script /usr/share/nmap/scripts/smb-os-discovery.nse -p445 $HOST | grep "Domain name:")
	fi
	hostname_found=$(nmap -Pn -T4 --script /usr/share/nmap/scripts/smb-os-discovery.nse -p445 $HOST | grep "Computer name:")
	if [ -z $hostname_found ]; then
		hostname_found=$(nmap -Pn -T4 -sV -sC -p389 $HOST | grep "commonName" | cut -d " " -f 4 | cut -d "=" -f 2)
	fi
	if [ -z $hostname_found ]; then
		hostname_found=$(nmap -Pn -T4 -sV -p389 $HOST | grep "Host:" | cut -d " " -f 4 | tr -d ";")
	fi
	echo
	printf "${YELLOW}[+] Discovered domain - ${LIGHT_CYAN}$domain_found ${DULL_YELLOW}(If found then, 70%% accurate)${NC}\n"
	printf "${YELLOW}[+] Discovered hostname - ${LIGHT_CYAN}$hostname_found ${DULL_YELLOW}(If found then, 70%% accurate)${NC}\n"
	echo	

fi
ELAPSED="$(($SECONDS / 3600))hrs $((($SECONDS / 60) % 60))min $(($SECONDS % 60))sec"
printf "${YELLOW}[+] Duration: ${NC}$ELAPSED\n"
printf "${BLUE}[+] DONE.${NC}\n"
