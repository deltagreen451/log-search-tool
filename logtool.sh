#!/bin/bash

#SOftware Based Solution Assignment 3 for CSI6203 Scripting Languages 
#Mr Loh Heng Sin
#10540894

getmenu () { #function to generate a menu for file selection
    FILE=sel.tmp #declares temporary file sel.tmp for selection menu
    if test -f "$FILE"; then #checks if sel.tmp already exist from previous script use and removes old one
        rm sel.tmp
        ls serv*.csv > sel.tmp
    else #generates sel.tmp 
        ls serv*.csv > sel.tmp
    fi
    maxchoice=$(sed -n \$= sel.tmp) #declares maximum number of .csv files
}

getfile () {
while :
do
    echo -e "Log files found:" #displays the log files discovered
    awk '{print NR ") " $0}' sel.tmp
    read -p "Select file [1 - $maxchoice] or [0] for Main Menu: " fchoice #gets user choice for log file

    if [ -z $fchoice ] || [[ $((fchoice)) != $fchoice ]] || [ $fchoice -gt $maxchoice ]; then #check if file choice is invalid
        echo -e "\nInvalid choice!\n"
    elif [ $fchoice = "0" ]; then #menu option to return to main menu loop
        echo -e "\nReturning to Main Menu\n"
        break
    else
        logfile=$(awk -v fc=$fchoice 'NR==fc' sel.tmp) #declares logfile to be used
        echo -e "\nFile chosen is $logfile\n"
        getsusmenu #function call to get suspicious criteria
    fi
done
}

genlog () { #function to create log file 
name=$(echo "$logfile" | sed 's/\.[^.]*$//') #strips .csv extension from log file
now=$(date +'%d-%m-%Y-%Hh%Mm%Ss') #declares current date and time stamp format
storefile="search_results_$name_$now.csv" #declares log file name format
touch $storefile #creates log file for population
echo "Date,Dura,Prot,SRC IP,,SRC PRT,DES IP,,DES PRT,Packets,Bytes,Flows,Flags,TOS,Class" | tr ',' '\t' >> $storefile #creates column headers

cat $logfile | grep "suspicious" | grep "$suscrit" | tr ',' '\t' >> $storefile #populates log file based on user search criteria

case $searchtype in #populates log file based on user search criteria
PROTOCOL) cat $logfile | grep "suspicious" | awk -v pat="$suscrit" 'IFS=","; {$3~/pat/}' | tr ',' '\t' >> $storefile ;;
SRCIP) cat $logfile | grep "suspicious" | awk -v pat="$suscrit" 'IFS=","; {$4~/pat/}' | tr ',' '\t' >> $storefile ;;
SRCPORT) cat $logfile | grep "suspicious" | awk -v pat="$suscrit" 'IFS=","; {$5~/pat/}' | tr ',' '\t' >> $storefile ;;
DESTIP) cat $logfile | grep "suspicious" | awk -v pat="$suscrit" 'IFS=","; {$6~/pat/}' | tr ',' '\t' >> $storefile ;;
DESTPORT) cat $logfile | grep "suspicious" | awk -v pat="$suscrit" 'IFS=","; {$7~/pat/}' | tr ',' '\t' >> $storefile ;;
DATPKT) cat $logfile | grep "suspicious" | awk -v pat="$suscrit" 'IFS=","; {$8~/pat/}' | tr ',' '\t' >> $storefile 
awk '{s=s+int(+$8)} END {print "Total Packets:" s}' $storefile #totals and prints the Packets
;;
BYTES) cat $logfile | grep "suspicious" | awk -v pat="$suscrit" 'IFS=","; {$9~/pat/}' | tr ',' '\t' >> $storefile 
awk '{s=s+int($9)} END {print "Total Bytes:" s}' $storefile #totals and prints the Bytes
;;
esac
echo -e "\n$storefile created\n"
}

showsearchmenu () { #function to get user selection for search
echo "Server Access Log Search Criteria"
echo "  1) Protocol"
echo "  2) Source IP"
echo "  3) Source Port"
echo "  4) Destination IP"
echo "  5) Destination Port"
echo "  6) Data Packets"
echo "  7) Bytes"
echo "  0) Exit Program"
}

getsusmenu () { #Function to show suspicious criteria for user to choose 
case $searchtype in #creates temporary menu sus.tmp of unique entries based on search criteria
PROTOCOL) cat $logfile | grep "suspicious" | awk -F "," '{ print $3 }' | sort | uniq > sus.tmp ;;
SRCIP) cat $logfile | grep "suspicious" | awk -F "," '{ print $4 }' | sort -n | uniq > sus.tmp ;;
SRCPORT) cat $logfile | grep "suspicious" | awk -F "," '{ print $5 }' | sort -n | uniq > sus.tmp ;;
DESTIP) cat $logfile | grep "suspicious" | awk -F "," '{ print $6 }' | sort -n | uniq > sus.tmp ;;
DESTPORT) cat $logfile | grep "suspicious" | awk -F "," '{ print $7 }' | sort -n | uniq > sus.tmp ;;
DATPKT) cat $logfile | grep "suspicious" | awk -F "," '{ print $8 }' | sort -n | uniq > sus.tmp ;;
BYTES) cat $logfile | grep "suspicious" | awk -F "," '{ print $9 }' | sort -n | uniq > sus.tmp ;;
esac

maxsuschoice=$(sed -n \$= sus.tmp) #declares maximum number of suspicious types for search criteria
while :
do
    echo -e "\nSuspicious entries found:" #displays the suspicious types discovered
    awk '{ print NR ") " $0 }' sus.tmp
    read -p "Select criteria [1 - $maxsuschoice] or [0] for previous Menu: " suschoice #gets user choice for criteria

    if [ -z $suschoice ] || [[ $((suschoice)) != $suschoice ]] || [ $suschoice -gt $maxsuschoice ]; then #check if criteria is invalid
        echo -e "\nInvalid choice!\n"
    elif [ $suschoice = "0" ]; then #menu option to return to main menu loop
        echo -e "\nReturning to previous Menu\n"
        break
    else
        suscrit=$(awk -v fc=$suschoice 'NR==fc' sus.tmp) #declares criteria to be used
        echo -e "\nGenerating Log File...\n"
        genlog #calls function to generate log file based on user criteria
        break
    fi
done
}

#############################
### Start of main program ###
#############################

getmenu #function call to generate access log menu
fmtbl="%-9s %-10s %-6s %-10s %-6s %-5s %-6s %-10s" #declares formatting table for file output in columns

while : #begins main loop until quit is selected
    do
        showsearchmenu #function call to show menu selection for search criteria
        read -p "Please select [1 - 7] or [0] to quit: " usrsearch #gets user search criteria
        if [ -z $usrsearch ] || [[ $((usrsearch)) != $usrsearch ]]; then
            echo -e "\nInvalid Selection!\n"
        else 
            case $usrsearch in
            1) searchtype="PROTOCOL"
                echo -e "\nProtocol selected\n"
                getfile #call to function to get user selection for file to apply search to
            ;;
            2) searchtype="SRCIP"
                echo -e "\nSource IP selected\n"
                getfile #call to function to get user selection for file to apply search to
            ;;
            3) searchtype="SRCPORT"
                echo -e "\nSource Port selected\n"
                getfile #call to function to get user selection for file to apply search to
            ;;
            4) searchtype="DESTIP"
                echo -e "\nDestination IP selected\n"
                getfile #call to function to get user selection for file to apply search to
            ;;
            5) searchtype="DESTPORT"
                echo -e "\nDestination Port selected\n"
                getfile #call to function to get user selection for file to apply search to
            ;;
            6) searchtype="DATPKT"
                echo -e "\nData Packet selected\n"
                getfile #call to function to get user selection for file to apply search to
            ;;
            7) searchtype="BYTES"
                echo -e "\nBytes selected\n"
                getfile #call to function to get user selection for file to apply search to
            ;;
            8 | 9) echo -e "\nInvalid Selection\n";; #for invalid selection
            0) echo -e "\nGood Bye!\n" #exits program
                rm sel.tmp #removes temporary files used as part of cleanup
                rm sus.tmp
                exit 1
            ;;
            esac
        fi
    done #end of main loop

exit 0