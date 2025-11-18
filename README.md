# Professional Pentesting Zsh Configuration

A production-ready Zsh configuration optimized for **Red Team operations, Penetration Testing engagements, and security assessments**. This configuration replaces redundant aliases with intelligent functions that automate workflow management, maintain evidence organization, and accelerate common exploitation tasks.

## Overview

This configuration addresses common inefficiencies in penetration testing workflows by implementing:

- **Persistent target management** across terminal sessions
- **Automated evidence organization** with structured directory creation
- **Centralized configuration** through environment variables
- **Streamlined exploitation workflows** with payload generation and shell management

## Architecture

The configuration follows a **Category -> Action** structure, eliminating redundancy and improving maintainability. All hardcoded paths are centralized in environment variables, making the configuration portable across different Linux distributions and penetration testing frameworks.

## Key Features

### Target Management

- **Persistent Target Variables**: Set `RHOST` once using `settarget <IP>`, and it automatically persists across all new terminal tabs and windows via a temporary file mechanism
- **Cross-Session Persistence**: Target information is stored in `/tmp/target_ip`, ensuring continuity across terminal sessions
- **Quick Target Operations**: `showtarget` displays current target, `cleartarget` removes it

### Reconnaissance Automation

- **Organized Output**: All scanning functions automatically create `nmap/` directories to maintain clean engagement folders
- **Standardized Scans**: Pre-configured scan types (`nscan`, `nscan-all`, `nscan-udp`, `nscan-vuln`) with consistent output naming
- **Evidence Preservation**: All scan results are saved with descriptive filenames for reporting and documentation

### Shell Management

- **Enhanced Listeners**: Automatic `rlwrap` integration for improved shell interaction (history, arrow keys, line editing)
- **TTY Stabilization**: Quick reference function (`fix-tty`) for upgrading unstable shells to fully interactive TTYs
- **Payload Generation**: Instant reverse shell payload generation (Bash, Python, PowerShell) with Base64 encoding support

### Web Application Testing

- **Optimized Fuzzing**: Pre-configured directory, VHOST, and parameter fuzzing with centralized wordlist management
- **Flexible Servers**: HTTP and SMB server functions with configurable ports and share names
- **Wordlist Centralization**: Global variables for common wordlists (SecLists, RockYou) eliminate hardcoded paths

### Active Directory Testing

- **Impacket Integration**: Streamlined aliases for common AD enumeration and exploitation tasks
- **Credential Extraction**: Quick access to secrets dumping and AS-REP roasting functions

## Dependencies

### Required

```bash
sudo apt update
sudo apt install -y rlwrap xclip
```

### Recommended

```bash
sudo apt install -y bat fzf
# For latest fzf version, install from git:
# git clone --depth 1 https://github.com/junegunn/fzf.git ~/.fzf && ~/.fzf/install
```

### Tool Requirements

This configuration assumes a standard penetration testing environment with:

- Nmap
- Netcat (nc)
- Python 3
- FFuf or Gobuster
- John the Ripper
- Hashcat
- Impacket suite (for AD testing)
- Metasploit Framework

## Installation

### Step 1: Backup Current Configuration

```bash
cp ~/.zshrc ~/.zshrc.bak
```

### Step 2: Integrate Configuration

Append the contents of `hacking_aliases.zsh` to your `~/.zshrc` file:

```bash
cat hacking_aliases.zsh >> ~/.zshrc
```

Alternatively, source it directly in your `.zshrc`:

```bash
echo "source $(pwd)/hacking_aliases.zsh" >> ~/.zshrc
```

### Step 3: Configure Path Variables

Edit the global variables section at the top of `hacking_aliases.zsh` to match your system:

```bash
export WLISTS="/usr/share/wordlists"
export ROCKYOU="$WLISTS/rockyou.txt"
export SECLISTS="$WLISTS/seclists"
```

Adjust these paths if your wordlists are located elsewhere (e.g., `/opt/SecLists`, custom locations).

### Step 4: Reload Configuration

```bash
source ~/.zshrc
```

Or use the provided alias:

```bash
reload
```

## Usage Examples

### Engagement Initialization

```bash
# Create engagement directory structure
ctf-setup client_engagement_2024

# Set target IP (persists across all terminals)
settarget 192.168.1.100

# Verify target is set
showtarget
```

### Reconnaissance Phase

```bash
# Initial TCP scan with service detection
nscan

# Full port scan (all 65535 ports)
nscan-all

# UDP enumeration (top 100 ports)
nscan-udp

# Vulnerability scanning
nscan-vuln
```

All results are automatically saved to `nmap/` directory with descriptive filenames.

### Web Application Testing

```bash
# Directory fuzzing
fuzz-dir http://$RHOST

# Virtual host enumeration
fuzz-vhost http://$RHOST

# Parameter fuzzing
fuzz-params http://$RHOST/admin.php

# Start HTTP server for file transfer (port 80)
www 80

# Start HTTP server on non-privileged port
serve 8080

# Start SMB server for Windows target file transfer
smb-server fileshare
```

### Exploitation Workflow

**Terminal 1 - Listener Setup:**

```bash
# Enhanced listener with rlwrap (history, arrow keys)
listen 443
```

**Terminal 2 - Payload Generation:**

```bash
# Get VPN IP and copy to clipboard
myvpnip

# Generate Bash reverse shell (Base64 encoded)
gen-rev 10.10.14.8 443

# Generate Python reverse shell
gen-rev-python 10.10.14.8 443

# Generate PowerShell reverse shell
gen-rev-ps 10.10.14.8 443
```

**Terminal 3 - Shell Stabilization:**

After receiving a shell, use `fix-tty` to display the commands needed to upgrade to a fully interactive TTY.

### Password Cracking

```bash
# John the Ripper with RockYou wordlist
jtr hashes.txt

# View cracked passwords
jtr-show

# Hashcat with custom mode
hashcat-quick 1000 hashes.txt $ROCKYOU
```

### Active Directory Testing

```bash
# AS-REP Roasting (no pre-auth required)
imp-getnpusers DOMAIN/ -usersfile users.txt -dc-ip 10.10.10.1

# Dump NTLM hashes from DC
imp-secrets DOMAIN/user@10.10.10.1

# Full secrets dump
imp-secrets-full DOMAIN/user@10.10.10.1
```

## Command Reference

### Target Management

| Command | Description |
|---------|-------------|
| `settarget <IP>` | Set global target IP (persists across terminal sessions) |
| `showtarget` | Display current target configuration |
| `cleartarget` | Remove target and clear persistent storage |

### Reconnaissance

| Command | Description |
|---------|-------------|
| `nscan` | Standard TCP scan with service detection and default scripts |
| `nscan-all` | Full port scan (all 65535 TCP ports) |
| `nscan-udp` | Fast UDP scan (top 100 ports) |
| `nscan-vuln` | Vulnerability scan using Nmap NSE scripts |
| `nscan-quick` | Quick scan (top 1000 ports, fast timing) |

### Web Application Testing

| Command | Description |
|---------|-------------|
| `www <PORT>` | Start Python HTTP server (requires sudo for ports < 1024, default: 80) |
| `serve <PORT>` | Start Python HTTP server on non-privileged port (default: 8000) |
| `smb-server <SHARE>` | Start Impacket SMB server with specified share name |
| `fuzz-dir <URL>` | Directory fuzzing with SecLists wordlists |
| `fuzz-vhost <URL>` | Virtual host/subdomain enumeration |
| `fuzz-params <URL>` | Parameter fuzzing for web applications |

### Shell Management

| Command | Description |
|---------|-------------|
| `listen <PORT>` | Start Netcat listener with rlwrap (enhanced shell interaction) |
| `listen-simple <PORT>` | Start basic Netcat listener (fallback if rlwrap unavailable) |
| `gen-rev <IP> <PORT>` | Generate Base64-encoded Bash reverse shell payload |
| `gen-rev-python <IP> <PORT>` | Generate Python reverse shell payload |
| `gen-rev-ps <IP> <PORT>` | Generate PowerShell reverse shell payload |
| `fix-tty` | Display commands to stabilize and upgrade TTY shell |

### Password Cracking

| Command | Description |
|---------|-------------|
| `jtr <HASH_FILE>` | John the Ripper with RockYou wordlist |
| `jtr-show` | Display cracked passwords from John database |
| `hashcat-quick <MODE> <HASH_FILE> <WORDLIST>` | Quick Hashcat attack with specified mode |

### Active Directory

| Command | Description |
|---------|-------------|
| `imp-getnpusers` | AS-REP Roasting (users without pre-authentication) |
| `imp-secrets` | Dump NTLM hashes from Domain Controller |
| `imp-secrets-full` | Full secrets dump from Domain Controller |

### Utilities

| Command | Description |
|---------|-------------|
| `myvpnip` | Copy tun0 interface IP address to clipboard |
| `ip-local` | Display local IPv4 addresses |
| `ip-public` | Display public IP address |
| `mkcd <DIR>` | Create directory and change into it |
| `cl <DIR>` | Change directory and list contents |
| `bininfo <FILE>` | Display binary file information (file type, strings, libraries) |
| `extract-strings <FILE>` | Extract relevant strings (flags, passwords, keys) from binary |
| `ctf-setup <NAME>` | Create organized directory structure for engagement |
| `addhost <IP> <HOSTNAME>` | Add entry to /etc/hosts file |
| `socks-proxy <USER@HOST> <PORT>` | Create SOCKS proxy via SSH |
| `fwport <REMOTE_IP> <REMOTE_PORT> <LOCAL_PORT> <SSH_TARGET>` | Port forwarding via SSH |

## Configuration Customization

### Environment Variables

Modify the following variables at the top of `hacking_aliases.zsh` to match your environment:

```bash
export WLISTS="/usr/share/wordlists"      # Base wordlist directory
export ROCKYOU="$WLISTS/rockyou.txt"      # RockYou wordlist path
export SECLISTS="$WLISTS/seclists"        # SecLists directory
export TARGET_FILE="/tmp/target_ip"       # Target persistence file
```

### Distribution-Specific Paths

For non-Kali distributions, update paths accordingly:

- **Parrot Security**: Paths typically match Kali
- **Ubuntu/Debian**: May require manual SecLists installation
- **Arch Linux**: Wordlists may be in `/usr/share/wordlists` or `/opt/wordlists`
- **Custom Installations**: Update paths to match your wordlist locations

## Best Practices

### Engagement Organization

1. **Use `ctf-setup`** at the start of each engagement to create organized directory structures
2. **Set target immediately** with `settarget` to avoid IP repetition
3. **Leverage automatic directory creation** - functions like `nscan` create `nmap/` automatically

### Evidence Management

1. **All scan results** are automatically organized in subdirectories
2. **Use descriptive engagement names** when creating directories
3. **Maintain clean root directories** - let functions handle organization

### Security Considerations

1. **Verify target IPs** before setting them globally
2. **Clear targets** with `cleartarget` at the end of engagements
3. **Review generated payloads** before execution
4. **Use encrypted channels** for sensitive data transfer

## Troubleshooting

### rlwrap Not Available

If `rlwrap` is not installed, the `listen` command will fail. Install it or use `listen-simple` as a fallback:

```bash
sudo apt install rlwrap
```

### Wordlist Paths Not Found

Update the `WLISTS`, `SECLISTS`, and `ROCKYOU` variables at the top of the configuration file to match your system's wordlist locations.

### Target Not Persisting

Ensure `/tmp` is writable and not mounted with `noexec`. The target file is stored at `/tmp/target_ip`. If issues persist, modify `TARGET_FILE` variable to use a different location (e.g., `~/.pentest_target`).

### xclip Not Working

If clipboard functions fail, install `xclip`:

```bash
sudo apt install xclip
```

For Wayland environments, consider using `wl-clipboard` instead.

## License

This configuration is provided as-is for authorized security testing and educational purposes only.

## Disclaimer

**This configuration is intended solely for authorized security testing, penetration testing engagements, and educational purposes. Unauthorized access to computer systems is illegal and may result in criminal prosecution. Users are responsible for ensuring they have proper authorization before using these tools and techniques.**

---

*Last Updated: 2024*
