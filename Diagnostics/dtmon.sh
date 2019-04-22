#!/bin/bash

@"
Documentation
    Monitor one or more targets for network downtime, and output 
    how long they were down for.

    It works by repeatedly pinging the targets. Once there's no
    response, it keeps pinging until it gets a response again, and
    calculates downtime based on timestamps output by ping.

Setup
    Dependencies: bash, iputils (for ping), and bc.

    On Ubuntu, install bc with 'sudo apt install bc'.

    To run the script, you can use a Linux VM or WSL (Windows
    Subsystem for Linux). WSL is recommended. Install guide for
    Windows Server: 
        https://docs.microsoft.com/en-us/windows/wsl/install-on-server

Usage
    usage: dtmon.sh [-?] [-v] [-i interval] [-l min_lost] targets...

    To stop moinotring, press Ctrl+C.

    Option	    Description
    ------      -----------
    -?          Display the above usage text.
    -v	        Verbose mode

    -i interval	The amount of time, in seconds, between pings.
                Values less than 0.2 require root (required by
                ping). Defaults to 0.2 seconds.

    -l min_lost	Minimum number of sequential lost packets before
                a target is considered down. Defaults to 2.

    targets...	Whitespace separated list of hostnames and/or IPs
                to monitor.

Output
    Outputs 'Monitoring...' once all targets are being monitored.

    By default, there's no output until one of the targets goes
    down and then back up again, at which point it will output
    a message like the one below. The ± 0.2 seconds is the ping
    interval used, since you can't know precisely when a target
    went up/down between pings. Therefore, it DOES NOT represent
    the total amount of error.

        10.11.12.1 was down for 6.417475 ± 0.2 seconds.

    With verbose, it will output when a target first goes down:

        10.11.12.1 is down.

Examples
    ./dtmon.sh 10.22.33.10 10.22.33.20 10.22.33.30
        Monitor 3 different IP addresses for downtime.

    sudo ./dtmon.sh -i 0.1 $(< ips.txt)
        Run as root with a 0.1 second interval, targeting the IPs listed in the file 'ips.txt'.

    ./dtmon.sh bing.com | tee out.txt
        Monitor bing.com for downtime, and tee the output to a file.
"@

if [[ -z $(command -v "bc") ]]; then
    echo "dtmon: bc is not installed" >&2
    exit 1
fi

declare -a ips
declare interval=0.2
declare min_lost=2 # min number of sequential lost packets before a target is considered down
#declare min_response=1 # (not implemented) min number of sequential responses before a target is considered up
declare verbose=
declare usage="usage: dtmon.sh [-?] [-v] [-i interval] [-l min_lost] targets..."

while [[ $# -gt 0 ]]; do
	case ${1,,} in
        -\?|-h)
            echo $usage
            exit 0
            ;;
        -i)
            interval=$2
            shift
            ;;
        -l)
            min_lost=$2
            shift
            ;;
#        -r)
#            min_response=$2
#            shift
#            ;;
        -v)
            verbose="on"
            ;;
        -*)
            echo "dtmon: Unrecognized option $1" >&2
            echo $usage
            exit 1
            ;;
		*)
            ips+=("$1")
			;;
	esac
	shift
done

if [[ -z $ips ]]; then
    echo "dtmon: no targets specified." >&2
    exit 1
fi

if [[ $min_lost -lt 1 ]]; then
    min_lost=1
fi

function extract_timestamp() {
    [[ $1 =~ ^\[([0-9]+\.[0-9]+)\] ]]
    echo "${BASH_REMATCH[1]}"
}

trap 'kill $(jobs -p) >& /dev/null' INT TERM EXIT

for ip in ${ips[@]}; do
    (
    lost_packets=0
    ping -DO -i $interval $ip  | while read line; do
        if [[ $line =~ "no answer yet" ]]; then
            ((lost_packets++))
            if [[ -z $first_dropped ]]; then
                first_dropped=$(extract_timestamp $line)
            fi

            if [[ $verbose && $lost_packets = $min_lost ]]; then
                echo "$ip is down."
            fi
        elif [[ $first_dropped ]]; then
            if [[ $lost_packets -ge $min_lost ]]; then
                downtime_end=$(extract_timestamp $line)
                duration=$(bc <<< "$downtime_end - $first_dropped + $interval")
                echo "$ip was down for $duration ± $interval seconds."
            fi
            # reset vars
            lost_packets=0
            first_dropped=
        fi
    done
    ) &
done

echo "Monitoring..."

wait $!