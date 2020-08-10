#!/bin/bash
#coding:utf-8
#title:scanNport.sh
#author:hacknonym

#terminal text color code
grey='\e[0;37m'
red='\e[0;31m'
yellow='\e[0;33m'

function help(){
	echo -e """Usage : ./scanNport.sh [[--scan] [--port] [--all]]
Scan the network host with ICMP (ping) request and detect ports with TCP request.

  -s, --scan       simple ping scan of hosts only with ICMP request
  -p, --port       make a scan for your port(s)
  -a, --all        make a scan for all ports
  -h, --help       show this help and ends

Examples:
  scanNport 192.168.0.0/24 --scan #Make a simple PING scan
  scanNport 192.168.0.50          #Default scan with commom TCP ports
  scanNport 192.168.0.50 --all
  scanNport 192.168.1.0/24 --port 22,23,80"""
}

function startup(){
	which ping 1> /dev/null 2>&1 || {
    	echo -e "$grey[x] ping$yellow not installed$grey"
    	read -p "Push ENTER to install" enter
    	if [ $EUID -eq 0 ] ; then 
	  		echo -ne "[+] Installation of $yellow$1$grey in progress..."
	    	sudo apt-get install -y $1 1> /dev/null
	    	echo -e "OK$grey"
	  	else
	  		echo -e "[x] You don't have root privileges"
	  		exit 0
		fi
    }

    if ip a | grep -A2 "LOWER_UP" | grep -v "LOOPBACK" | grep -e "inet" | awk '{print $2}' | cut -d '/' -f 1 | grep -v "127.0.0.1" 1> /dev/null ; then
    	echo -n
    else
    	echo -e "[x] Not connected to the network"
    	exit 0
	fi
}

function analysis_ip(){
	#Analyse of $1 <seg0>.<seg1>.<seg2>
	seg0=$(echo -e "$1" | cut -d '.' -f 1)
    seg1=$(echo -e "$1" | cut -d '.' -f 2)
    seg2=$(echo -e "$1" | cut -d '.' -f 3)

    if [ $seg0 -lt 0 -o $seg0 -gt 254 ] ; then
    	echo -e "Error IP address: $1 cannot be scanned"
		exit 0
    elif [ $seg1 -lt 0 -o $seg1 -gt 254 ] ; then
    	echo -e "Error IP address: $1 cannot be scanned"
		exit 0
    elif [ $seg2 -lt 0 -o $seg2 -gt 254 ] ; then
    	echo -e "Error IP address: $1 cannot be scanned"
		exit 0
    fi

    #Network address
	if echo -e "$1" | grep -e "/" 1> /dev/null ; then
		simple_host=0

		#Analyse <seg3> = 0
		seg3=$(echo -e "$1" | cut -d '/' -f 1 | cut -d '.' -f 4)
		if [ $seg3 -ne 0 ] ; then
			echo -e "Error Range of IP address: $1 cannot be scanned"
			exit 0
		fi

		#Analyse </mask>    8 < x < 32
		mask=$(echo -e "$1" | cut -d '/' -f 2)
		if [ $mask -lt 8 -o $mask -ge 32 ] ; then
			echo -e "Error Mask: '$mask' < 8 or '$mask' >= 32"
			exit 0
		fi

		#Number of characters min: x.x.x.0/x    max: xxx.xxx.xxx.000/xx
		if [ $(echo -e "$1" | wc -c) -lt 10 -o $(echo -e "$1" | wc -c) -gt 19 ] ; then
        	echo -e "Error IP address: $1 invalid format"
			exit 0
		fi

		ip_addr="$seg0.$seg1.$seg2.$seg3/$mask"

		modulo8=$(($mask % 8))

		temp=$(($mask / 8))
		nb_bytes=$((4 - $temp))

		if [ $nb_bytes -eq 1 ] ; then
			case $modulo8 in
				#Number of hosts
				0 ) limit_host=$((256 - 2));;
				1 ) limit_host="128";;
				2 ) limit_host="64";;
				3 ) limit_host="32";;
				4 ) limit_host="16";;
				5 ) limit_host="8";;
				6 ) limit_host="4";;
				7 ) limit_host="2";;
				8 ) limit_host="1";;
				* ) echo -e "Error Mask: $mask" ; exit 0;;
			esac
			nb_tot_hosts=$limit_host

		elif [ $nb_bytes -gt 1 -a $nb_bytes -lt 4 ] ; then
			case $modulo8 in
				#Number of hosts
				0 ) limit_subnet=$((256 - 1));;
				1 ) limit_subnet=$((128 - 1));;
				2 ) limit_subnet=$((64 - 1));;
				3 ) limit_subnet=$((32 - 1));;
				4 ) limit_subnet=$((16 - 1));;    # -> e.g. /20 -> 11111111.11111111.11110000.00000000
				5 ) limit_subnet=$((8 - 1));;     #             -> -.-.(0..15).(1..254)  ->  16 x 254 = 4064 hosts
				6 ) limit_subnet=$((4 - 1));;
				7 ) limit_subnet=$((2 - 1));;
				8 ) limit_subnet=$((1 - 1));;
				* ) echo -e "Error Mask: $mask" ; exit 0;;
			esac

			case $nb_bytes in
				2 ) nb_tot_hosts=$((($limit_subnet + 1) * 254));;
				3 ) nb_tot_hosts=$((($limit_subnet + 1) * 256 * 254));;
			esac
		fi

		echo -e "Total number of hosts to scan: $nb_tot_hosts\n"

		#For -> 10.1.1.0
		#e.g.  /24, 1 bytes, 1    subnet,          254 hosts:       10.1.1.(1..254)
		#e.g.  /20, 2 bytes, 16   subnet,          4_064 hosts:     10.1.(0..15).(1..254)
		#e.g.  /16, 2 bytes, 256  subnet,          65_024 hosts:    10.1.(0..255).(1..254)
		#e.g.  /11, 3 bytes, 8192 (32x256) subnet, 2_080_768 hosts: 10.(0..31).(0..255).(1..254)

	#Simple Host
	else
		simple_host=1
		#Analyse <seg3>
        seg3=$(echo -e "$1" | cut -d '.' -f 4)
        if [ $seg3 -le 0 -o $seg3 -gt 254 ] ; then
        	echo -e "Error IP address: $1 cannot be scanned"
			exit 0
        fi

		#Number of characters min: x.x.x.x    max: xxx.xxx.xxx.xxx
		if [ $(echo -e "$1" | wc -c) -lt 8 -o $(echo -e "$1" | wc -c) -gt 16 ] ; then
        	echo -e "Error IP address: $1 invalid format"
			exit 0
		fi

		ip_addr="$seg0.$seg1.$seg2.$seg3"
	fi
}

function ping_scan(){
	launch_scan 0
}

function scan_all_ports(){
	launch_scan 1 0
}

function scan_specific_ports(){
	c=0
	for i in $(echo -e "$1" | tr ',' ' ') ; do
		tab_ports[$c]="$i"
		c=$(($c + 1))
	done

	launch_scan 1 1
}

function scan_common_ports(){
	#https://packetlife.net/media/library/23/common-ports.pdf and more
	tab_ports=(7 19 20 21 22 23 25 42 43 49 53 67 68 69 70 79 80 88 102 110 113 119 123 135 137 139 143 161 162 177 179 201 264 318 381 383 389 411 412 443 445 464 465 497 500 512 513 514 515 520 521 540 554 546 547 560 563 587 591 593 631 636 639 646 691 860 873 902 989 990 993 995 1025 1026 1029 1080 1194 1214 1241 1311 1337 1433 1434 1512 1589 1701 1723 1725 1741 1755 1812 1813 1863 1900 1985 2000 2002 2049 2082 2083 2100 2222 2302 2483 2484 2745 2967 3050 3074 3124 3127 3128 3222 3260 3306 3389 3689 3690 3724 3784 3785 4333 4444 4664 4672 4899 5000 5001 5004 5005 5050 5060 5190 5222 5223 5432 5500 5554 5631 5632 5800 5900 6000 6001 6112 6129 6257 6346 6347 6500 6566 6588 6665 6669 6679 6697 6699 6881 6999 6891 6901 6970 7212 7648 7649 8000 8080 8081 8086 8087 8118 8200 8443 8500 8767 8866 9100 9101 9103 9119 9800 9898 9988 9999 10000 10113 10116 11371 12035 12036 12345 13720 13721 14567 15118 19226 19638 20000 24800 25999 27015 27374 28960 31337 33434)
	
	c=0
	for i in $(seq 0 1000) ; do
		x=${tab_ports[$i]}
		if [ ! -z $x ] ; then
			c=$(($c + 1))
		fi
	done

	launch_scan 1 1
}

function launch_scan(){

	#$1 -> 0/1    ping / ping & ports
	#$2 -> 0/1    all ports / specific or common ports

	if [ $simple_host -eq 1 ] ; then
		if ping -c 1 -s 1 -W 1 -q $ip_addr | grep -e "1 received" 1> /dev/null ; then
			echo -e "Host $yellow$ip_addr$grey is Alive"
			#scan ports
			if [ $1 -eq 1 ] ; then
				#scan all ports
				if [ $2 -eq 0 ] ; then
					for p in $(seq 1 65535) ; do
						if echo "test" 2> /dev/null > /dev/tcp/$ip_addr/$p ; then
							echo -en "\r                                \n"
							echo -en "\033[1A"
							echo -e "\r> port $p"
						else
							echo -en "\r ($ip_addr) $p/65536"
						fi
					done
				#scan specific or common ports
				elif [ $2 -eq 1 ] ; then
					for p in $(seq 0 $(($c - 1))) ; do
						if echo "test" 2> /dev/null > /dev/tcp/$ip_addr/${tab_ports[$p]} ; then
							echo -en "\r                                \n"
							echo -en "\033[1A"
							echo -e "\r> port ${tab_ports[$p]}"
						else
							echo -en "\r ($ip_addr) ${tab_ports[$p]} - $(($p + 1))/$c"
						fi
					done
				fi
			fi
			echo -en "\r"
		fi
	else
		# /24 < x < /32
		if [ $nb_bytes -eq 1 ] ; then
			for i in $(seq 1 $limit_host) ; do
				if ping -c 1 -s 1 -W 1 -q $seg0.$seg1.$seg2.$i | grep -e "1 received" 1> /dev/null ; then
					echo -en "\r                    "
					echo -en "\n"
					echo -en "\033[1A"
					echo -e "Host $yellow$seg0.$seg1.$seg2.$i$grey is Alive"
					#scan ports
					if [ $1 -eq 1 ] ; then
						#scan all ports
						if [ $2 -eq 0 ] ; then
							for p in $(seq 1 65535) ; do
								if echo "test" 2> /dev/null > /dev/tcp/$seg0.$seg1.$seg2.$i/$p ; then
									echo -en "\r                                \n"
									echo -en "\033[1A"
									echo -e "\r> port $p"
								else
									echo -en "\r ($seg0.$seg1.$seg2.$i) $p/65536"
								fi
							done
						#scan specific or common ports
						elif [ $2 -eq 1 ] ; then
							for p in $(seq 0 $(($c - 1))) ; do
								if echo "test" 2> /dev/null > /dev/tcp/$seg0.$seg1.$seg2.$i/${tab_ports[$p]} ; then
									echo -en "\r                                \n"
									echo -en "\033[1A"
									echo -e "\r> port ${tab_ports[$p]}"
								else
									echo -en "\r ($seg0.$seg1.$seg2.$i) ${tab_ports[$p]} - $(($p + 1))/$c"
								fi
							done
						fi
					fi
					echo -en "\r                                  "
				else
					echo -en "\r $seg0.$seg1.$seg2.$i/$mask"
				fi
			done
		# /16 < x < /24
		elif [ $nb_bytes -eq 2 ] ; then
			for i in $(seq 0 $limit_subnet) ; do
				echo -e "--Scan ($seg0.$seg1.$red$i$grey.0/$mask)--"
				for j in $(seq 1 254) ; do
					if ping -c 1 -s 1 -W 1 -q $seg0.$seg1.$i.$j | grep -e "1 received" 1> /dev/null ; then
						echo -en "\r                    "
						echo -en "\n"
						echo -en "\033[1A"
						echo -e "Host $yellow$seg0.$seg1.$i.$j$grey is Alive"
						#scan ports
						if [ $1 -eq 1 ] ; then
							#scan all ports
							if [ $2 -eq 0 ] ; then
								for p in $(seq 1 65535) ; do
									if echo "test" 2> /dev/null > /dev/tcp/$seg0.$seg1.$i.$j/$p ; then
										echo -en "\r                                \n"
										echo -en "\033[1A"
										echo -e "\r> port $p"
									else
										echo -en "\r ($seg0.$seg1.$i.$j) $p/65536"
									fi
								done
							elif [ $2 -eq 1 ] ; then
								for p in $(seq 0 $(($c - 1))) ; do
									if echo "test" 2> /dev/null > /dev/tcp/$seg0.$seg1.$i.$j/${tab_ports[$p]} ; then
										echo -en "\r                                \n"
										echo -en "\033[1A"
										echo -e "\r> port ${tab_ports[$p]}"
									else
										echo -en "\r ($seg0.$seg1.$i.$j) ${tab_ports[$p]} - $(($p + 1))/$c"
									fi
								done
							fi
						fi
						echo -en "\r                                  "
					else
						echo -en "\r $seg0.$seg1.$i.$j/$mask"
					fi
				done
				echo -en "\r                    "
				echo -en "\n"
			done
		# /8 < x < /16
		elif [ $nb_bytes -eq 3 ] ; then
			for i in $(seq 0 $limit_subnet) ; do
				echo -e "--Scan ($seg0.$red$i$grey.0.0/$mask)--\n"
				for j in $(seq 0 3) ; do   #192.168.(0).1  at  192.168.(255).254
					echo -e "--Scan ($seg0.$i.$red$j$grey.0/$mask)--"
					for k in $(seq 1 3) ; do     #192.168.0.(1)  at  192.168.0.(254)
						if ping -c 1 -s 1 -W 1 -q $seg0.$i.$j.$k | grep -e "1 received" 1> /dev/null ; then
							echo -en "\r                    "
							echo -en "\n"
							echo -en "\033[1A"
							echo -e "Host $yellow$seg0.$i.$j.$k$grey is Alive"
							#scan ports
							if [ $1 -eq 1 ] ; then
								#scan all ports
								if [ $2 -eq 0 ] ; then
									for p in $(seq 1 65535) ; do
										if echo "test" 2> /dev/null > /dev/tcp/$seg0.$i.$j.$k/$p ; then
											echo -en "\r                                \n"
											echo -en "\033[1A"
											echo -e "\r> port $p"
										else
											echo -en "\r ($seg0.$i.$j.$k) $p/65536"
										fi
									done
								elif [ $2 -eq 1 ] ; then
									for p in $(seq 0 $(($c - 1))) ; do
										if echo "test" 2> /dev/null > /dev/tcp/$seg0.$i.$j.$k/${tab_ports[$p]} ; then
											echo -en "\r                                \n"
											echo -en "\033[1A"
											echo -e "\r> port ${tab_ports[$p]}"
										else
											echo -en "\r ($seg0.$i.$j.$k) ${tab_ports[$p]} - $(($p + 1))/$c"
										fi
									done
								fi
							fi
							echo -en "\r                                  "
						else
							echo -en "\r $seg0.$i.$j.$k/$mask"
						fi
					done
					echo -en "\r                    "
					echo -en "\n"
				done
			done
		fi
	fi
}

if [ $# -eq 0 -o $# -gt 3 ] ; then
	help
	exit 0
else
	case $1 in
		"-h" | "--help" ) help ; exit 0;;
		* )
			startup
			analysis_ip "$1"

			if [ ! -z $2 ] ; then
				case $2 in
					"-s" | "--scan" ) ping_scan;;
					"-a" | "--all" ) scan_all_ports;;
					"-p" | "--port" )
						if [ ! -z $3 ] ; then
							scan_specific_ports $3
						else
							echo -e "Error undefined port(s) with option '$2'"
							echo -e "e.g.  scanNport 192.168.1.0/24 --port 22,23,80"
							exit 0
						fi;;
					* ) echo -e "Error parameter: $2" ; exit 0;;
				esac
			else
				scan_common_ports
			fi;;
	esac
fi
