#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

function error_message {
    echo -e "${RED}Erro: $1${NC}"
}

function success_message {
    echo -e "${GREEN}$1${NC}"
}

function warning_message {
    echo -e "${YELLOW}$1${NC}"
}

function info_message {
    echo -e "${BLUE}$1${NC}"
}

function highlight_message {
    echo -e "${MAGENTA}$1${NC}"
}

function action_message {
    echo -e "${CYAN}$1${NC}"
}

action_message "Atualizando pacotes..."
pkg update -y

action_message "Instalando Python..."
pkg install python -y

action_message "Instalando Git..."
pkg install git -y

action_message "Instalando bibliotecas Python necessárias..."
pip install requests rich python-whois

if [ ! -f scan.py ]; then
    error_message "O arquivo scan.py não foi encontrado no diretório atual."
    exit 1
fi

success_message "Instalação concluída!."

highlight_message "SiteScanner"
