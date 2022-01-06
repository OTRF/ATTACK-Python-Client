#!/bin/bash

# HELK script: install-helk-cti.sh
# HELK script description: Install Docker, Docker-Compoe and HELK CTI
# HELK build version: 0.9 (Alpha)
# Author: Roberto Rodriguez (@Cyb3rWard0g)
# License: BSD 3-Clause

if [[ $EUID -ne 0 ]]; then
   echo "[HELK-CTI-INSTALLATION-INFO] YOU MUST BE ROOT TO RUN THIS SCRIPT!!!" 
   exit 1
fi

LOGFILE="/var/log/helk-install.log"
echoerror() {
    printf "${RC} * ERROR${EC}: $@\n" 1>&2;
}

# *********** Check System Kernel Name ***************
systemKernel="$(uname -s)"

# ********** Install Curl ********************
install_curl(){
    echo "[HELK-CTI-INSTALLATION-INFO] Checking if curl is installed first"
    if [ -x "$(command -v curl)" ]; then
        echo "[HELK-CTI-INSTALLATION-INFO] curl is already installed"
    else
        echo "[HELK-CTI-INSTALLATION-INFO] curl is not installed"
        echo "[HELK-CTI-INSTALLATION-INFO] Installing curl before installing docker.."
        apt-get install -y curl >> $LOGFILE 2>&1
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echoerror "Could not install curl (Error Code: $ERROR)."
            exit 1
        fi
    fi
}

# *********** Building and Running HELK Images ***************
install_helk(){
    # ****** Building & running HELK ***********
    echo "[HELK-CTI-INSTALLATION-INFO] Building & running HELK via docker-compose"
    docker-compose up --build -d >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not run HELK via docker-compose (Error Code: $ERROR)."
        exit 1
    fi
}

# ****** Installing via convenience script ***********
install_docker(){
    echo "[HELK-CTI-INSTALLATION-INFO] Installing docker via convenience script.."
    curl -fsSL get.docker.com -o get-docker.sh >> $LOGFILE 2>&1
    chmod +x get-docker.sh >> $LOGFILE 2>&1
    ./get-docker.sh >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install docker via convenience script (Error Code: $ERROR)."
        if [ -x "$(command -v snap)" ]; then
            SNAP_VERSION=$(snap version | grep -w 'snap' | awk '{print $2}')
            echo "[HELK-CTI-INSTALLATION-INFO] Snap v$SNAP_VERSION is available. Trying to install docker via snap.."
            snap install docker >> $LOGFILE 2>&1
            ERROR=$?
            if [ $ERROR -ne 0 ]; then
                echoerror "Could not install docker via snap (Error Code: $ERROR)."
                exit 1
            fi
            echo "[HELK-CTI-INSTALLATION-INFO] Docker successfully installed via snap."            
        else
            echo "[HELK-CTI-INSTALLATION-INFO] Docker could not be installed. Check /var/log/helk-install.log for details."
            exit 1
        fi
    fi
}

install_docker_compose(){
    echo "[HELK-CTI-INSTALLATION-INFO] Installing docker-compose.."
    curl -L https://github.com/docker/compose/releases/download/1.19.0/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose >> $LOGFILE 2>&1
    chmod +x /usr/local/bin/docker-compose >> $LOGFILE 2>&1
    ERROR=$?
    if [ $ERROR -ne 0 ]; then
        echoerror "Could not install docker-compose (Error Code: $ERROR)."
        exit 1
    fi
}

get_host_ip(){
    # *********** Getting Host IP ***************
    # https://github.com/Invoke-IR/ACE/blob/master/ACE-Docker/start.sh
    echo "[HELK-CTI-INSTALLATION-INFO] Obtaining current host IP.."
    case "${systemKernel}" in
        Linux*)     host_ip=$(ip route get 1 | awk '{print $NF;exit}');;
        Darwin*)    host_ip=$(ifconfig en0 | grep inet | grep -v inet6 | cut -d ' ' -f2);;
        *)          host_ip="UNKNOWN:${unameOut}"
    esac
}

prepare_helk(){
    echo "[HELK-CTI-INSTALLATION-INFO] HELK IP set to ${host_ip}"
    if [ "$systemKernel" == "Linux" ]; then
        # Reference: https://get.docker.com/
        echo "[HELK-CTI-INSTALLATION-INFO] HELK identified Linux as the system kernel"
        echo "[HELK-CTI-INSTALLATION-INFO] Checking distribution list and version"
        # *********** Check distribution list ***************
        lsb_dist="$(. /etc/os-release && echo "$ID")"
        lsb_dist="$(echo "$lsb_dist" | tr '[:upper:]' '[:lower:]')"

        # *********** Check distribution version ***************
        case "$lsb_dist" in
            ubuntu)
                if [ -x "$(command -v lsb_release)" ]; then
                    dist_version="$(lsb_release --codename | cut -f2)"
                fi
                if [ -z "$dist_version" ] && [ -r /etc/lsb-release ]; then
                    dist_version="$(. /etc/lsb-release && echo "$DISTRIB_CODENAME")"
                fi
            ;;
            debian|raspbian)
                dist_version="$(sed 's/\/.*//' /etc/debian_version | sed 's/\..*//')"
                case "$dist_version" in
                    9)
                        dist_version="stretch"
                    ;;
                    8)
                        dist_version="jessie"
                    ;;
                    7)
                        dist_version="wheezy"
                    ;;
                esac
            ;;
            centos)
                if [ -z "$dist_version" ] && [ -r /etc/os-release ]; then
                    dist_version="$(. /etc/os-release && echo "$VERSION_ID")"
                fi
            ;;
            rhel|ol|sles)
                ee_notice "$lsb_dist"
                exit 1
                ;;
            *)
                if [ -x "$(command -v lsb_release)"]; then
                    dist_version="$(lsb_release --release | cut -f2)"
                fi
                if [ -z "$dist_version" ] && [ -r /etc/os-release ]; then
                    dist_version="$(. /etc/os-release && echo "$VERSION_ID")"
                fi
            ;;
        esac
        echo "[HELK-CTI-INSTALLATION-INFO] You're using $lsb_dist version $dist_version"            
        ERROR=$?
        if [ $ERROR -ne 0 ]; then
            echoerror "Could not verify distribution or version of the OS (Error Code: $ERROR)."
        fi

        # *********** Check if docker is installed ***************
        if [ -x "$(command -v docker)" ]; then
            echo "[HELK-CTI-INSTALLATION-INFO] Docker already installed"
            
        else
            echo "[HELK-CTI-INSTALLATION-INFO] Docker is not installed"

            # ****** Install Curl if it is not installed *********
            install_curl
            # ****** Installing Docker if it is not installed *********
            install_docker
        fi
        # ********** Check if docker-compose is installed *******
        if [ -x "$(command -v docker-compose)" ]; then
            echo "[HELK-CTI-INSTALLATION-INFO] Docker-compose already installed"
        else
            echo "[HELK-CTI-INSTALLATION-INFO] Docker-compose is not installed"

            # ****** Install Curl if it is not installed *********
            install_curl
            # ****** Installing Docker-Compose *******************
            install_docker_compose
        fi
    else
        # *********** Check if docker is installed ***************
        if [ -x "$(command -v docker)" ] && [ -x "$(command -v docker-compose)" ]; then
            echo "[HELK-CTI-INSTALLATION-INFO] Docker & Docker-compose already installed"
        else
            echo "[HELK-CTI-INSTALLATION-INFO] Install Docker & Docker-compose for $systemKernel"
            exit 1
        fi
    fi
    echo "[HELK-CTI-INSTALLATION-INFO] Dockerizing HELK.."
}

show_banner(){
    # *********** Showing HELK Docker menu options ***************
    echo " "
    echo "************************************************"	
    echo "**           HELK CTI Integration             **"
    echo "**                                            **"
    echo "** Author: Roberto Rodriguez (@Cyb3rWard0g)   **"
    echo "** Author: Jose Luis Rodriguez (@Cyb3rPandaH) **"
    echo "** HELK CTI version: 0.1.0 (BETA)             **"
    echo "** HELK ELK version: 6.3.0                    **"
    echo "** License: BSD 3-Clause                      **"
    echo "************************************************"
    echo " "
}

show_final_information(){
    echo " "
    echo " "
    echo "***********************************************************************************"
    echo "** [HELK-CTI-INSTALLATION-INFO] YOUR HELK CTI IS READY                               **"
    echo "** [HELK-CTI-INSTALLATION-INFO] USE THE FOLLOWING SETTINGS TO INTERACT WITH THE HELK **"
    echo "***********************************************************************************"
    echo " "
    echo "HELK KIBANA URL: http://${host_ip}"
    echo "HELK KIBANA & ELASTICSEARCH USER: helk"
    echo "HELK KIBANA & ELASTICSEARCH PASSWORD: hunting"
    echo " "
    echo "MITRE ATT&CK CTI is now available in the HELK !!!!"
    echo " "
    echo " "
    echo " "
}

show_banner
get_host_ip
prepare_helk
install_helk
sleep 180
show_final_information