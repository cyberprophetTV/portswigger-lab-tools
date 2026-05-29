#!/usr/bin/env bash
# =====================================================================
# bscp-setup.sh - Install the command-line tools needed for the BSCP exam
# =====================================================================
#
# What this installs / verifies:
#
#   ysoserial    Java deserialization-to-RCE gadget generator.
#                Stage 3 of the exam frequently needs this. Burp's
#                Java Deserialization Scanner extension is flaky -
#                being able to generate raw payloads at the terminal
#                is what saves you.
#                Source: https://github.com/frohoff/ysoserial
#
#   PHPGGC       PHP gadget chain generator - same idea for PHP apps.
#                Source: https://github.com/ambionics/phpggc
#
#   sqlmap       Automated SQL injection tool. Save a Burp request to
#                a file, run `sqlmap -r request.txt --batch`, and let
#                it grind on one tab while you hunt elsewhere.
#                Source: https://github.com/sqlmapproject/sqlmap
#
# Also VERIFIES (but doesn't install - they're usually pre-installed):
#
#   java         Required by ysoserial
#   php          Required by PHPGGC
#   python3      For local HTTP servers + this repo's tooling
#   ssh          For free SSH-based tunneling (serveo, localhost.run)
#   cloudflared  Cloudflare's free tunnel - most reliable free option
#                for exposing a local server to the internet
#                (alternative to the deprecated ngrok free tier).
#                Install yourself if missing (see docs/bscp-checklist.md).
#
# Usage:
#   bash bscp-setup.sh                  # install everything to /opt
#   bash bscp-setup.sh --prefix ~/tools # install under your home dir
#   bash bscp-setup.sh --check          # only verify, don't install
#
# Idempotent: safe to re-run. Updates anything that's out of date.

set -euo pipefail

PREFIX="/opt"
CHECK_ONLY=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)    PREFIX="$2"; shift 2 ;;
        --check)     CHECK_ONLY=1; shift ;;
        -h|--help)   sed -n '2,40p' "$0"; exit 0 ;;
        *)           echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

# ---- color helpers (matches the Python tools' palette) ----
if [[ -t 1 ]]; then
    GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'
    CYAN=$'\033[36m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
    GREEN=""; RED=""; YELLOW=""; CYAN=""; BOLD=""; DIM=""; RESET=""
fi

ok()    { echo "${GREEN}[+]${RESET} $*"; }
info()  { echo "${CYAN}[*]${RESET} $*"; }
warn()  { echo "${YELLOW}[!]${RESET} $*"; }
err()   { echo "${RED}[-]${RESET} $*"; }

# ---------------------------------------------------------------------
# VERIFY PREREQUISITES (java, php, python3, ssh) - don't install,
# just report. Modern Kali / Parrot / standard pentest VMs ship with
# these; if you're on something minimal you'll need to install them
# with your distro's package manager.
# ---------------------------------------------------------------------
check_cmd() {
    local cmd="$1" purpose="$2"
    if command -v "$cmd" >/dev/null 2>&1; then
        ok "$cmd  ($(command -v "$cmd"))  - $purpose"
        return 0
    else
        err "$cmd missing - needed for: $purpose"
        return 1
    fi
}

info "Verifying prerequisites..."
PREREQ_OK=1
check_cmd java     "ysoserial (.jar runtime)"      || PREREQ_OK=0
check_cmd php      "PHPGGC"                        || PREREQ_OK=0
check_cmd python3  "local HTTP server + this repo" || PREREQ_OK=0
check_cmd ssh      "SSH-based free tunneling (serveo/localhost.run)" || PREREQ_OK=0
check_cmd git      "cloning PHPGGC + sqlmap"       || PREREQ_OK=0
check_cmd curl     "downloading ysoserial release" || PREREQ_OK=0

# Optional tools - report but don't fail.
echo
info "Optional tools..."
if command -v cloudflared >/dev/null 2>&1; then
    ok "cloudflared - free Cloudflare tunnel (most reliable free option)"
else
    warn "cloudflared NOT installed - install for free local-server tunneling."
    warn "    Debian/Ubuntu: see https://pkg.cloudflare.com/index.html"
    warn "    Or use SSH fallbacks: 'ssh -R 80:localhost:8000 serveo.net'"
fi
if command -v ngrok >/dev/null 2>&1; then
    ok "ngrok"
else
    warn "ngrok NOT installed - optional (and now requires signup for tunnels)"
fi

if [[ "$PREREQ_OK" -eq 0 ]]; then
    err "Some prerequisites are missing. Install them with your"
    err "distro's package manager (apt install / dnf install / pacman -S)"
    err "and re-run this script."
    if [[ "$CHECK_ONLY" -ne 1 ]]; then exit 1; fi
fi

if [[ "$CHECK_ONLY" -eq 1 ]]; then
    echo
    info "--check mode: skipping installs."

    # Even in check mode, report which tools the installer would
    # have set up so the user knows what's missing.
    echo
    info "BSCP tools status:"
    for tool in ysoserial phpggc sqlmap; do
        if command -v "$tool" >/dev/null 2>&1; then
            ok "$tool  ($(command -v "$tool"))"
        else
            err "$tool NOT installed (re-run without --check to install)"
        fi
    done
    exit 0
fi

# ---------------------------------------------------------------------
# INSTALL ysoserial - Java deserialization gadget generator
# ---------------------------------------------------------------------
install_ysoserial() {
    local install_dir="${PREFIX}/ysoserial"
    local wrapper="/usr/local/bin/ysoserial"

    info "Installing ysoserial to ${install_dir}..."

    # Pre-built JAR is on the GitHub release page. We use the GitHub
    # API to find the latest "ysoserial-all.jar" asset URL so we don't
    # hard-code a version that goes stale.
    local jar_url
    jar_url=$(curl -fsSL https://api.github.com/repos/frohoff/ysoserial/releases/latest \
              | grep -oE 'https://[^"]+ysoserial-all\.jar' \
              | head -n1 || true)

    # Fallback: pinned release if API call fails (rate-limited / offline).
    if [[ -z "$jar_url" ]]; then
        warn "GitHub API rate-limited; using pinned 0.0.6 release URL."
        jar_url="https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-0.0.6-SNAPSHOT-all.jar"
    fi

    sudo mkdir -p "$install_dir"
    sudo curl -fsSL -o "$install_dir/ysoserial.jar" "$jar_url"

    # Wrapper script so `ysoserial CommonsCollections6 "curl ..."` Just Works.
    sudo tee "$wrapper" >/dev/null <<EOF
#!/usr/bin/env bash
# Auto-generated by bscp-setup.sh - wraps ysoserial.jar so it's on PATH.
exec java -jar "${install_dir}/ysoserial.jar" "\$@"
EOF
    sudo chmod +x "$wrapper"

    ok "ysoserial installed. Test: ysoserial CommonsCollections6 'id'"
}

# ---------------------------------------------------------------------
# INSTALL PHPGGC - PHP gadget chain generator
# ---------------------------------------------------------------------
install_phpggc() {
    local install_dir="${PREFIX}/phpggc"
    local wrapper="/usr/local/bin/phpggc"

    info "Installing PHPGGC to ${install_dir}..."

    if [[ -d "$install_dir/.git" ]]; then
        info "Updating existing checkout..."
        sudo git -C "$install_dir" pull --ff-only
    else
        sudo git clone --depth 1 https://github.com/ambionics/phpggc.git "$install_dir"
    fi

    sudo tee "$wrapper" >/dev/null <<EOF
#!/usr/bin/env bash
# Auto-generated by bscp-setup.sh - wraps phpggc so it's on PATH.
exec php "${install_dir}/phpggc" "\$@"
EOF
    sudo chmod +x "$wrapper"

    ok "PHPGGC installed. List chains: phpggc -l"
}

# ---------------------------------------------------------------------
# INSTALL sqlmap - automated SQL injection
# ---------------------------------------------------------------------
install_sqlmap() {
    local install_dir="${PREFIX}/sqlmap"
    local wrapper="/usr/local/bin/sqlmap"

    info "Installing sqlmap to ${install_dir}..."

    # Sqlmap's "dev" branch is what they recommend for engagements -
    # has newer payloads / fixes than the latest tagged release.
    if [[ -d "$install_dir/.git" ]]; then
        info "Updating existing checkout..."
        sudo git -C "$install_dir" pull --ff-only
    else
        sudo git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$install_dir"
    fi

    sudo tee "$wrapper" >/dev/null <<EOF
#!/usr/bin/env bash
# Auto-generated by bscp-setup.sh - wraps sqlmap so it's on PATH.
exec python3 "${install_dir}/sqlmap.py" "\$@"
EOF
    sudo chmod +x "$wrapper"

    ok "sqlmap installed. Test: sqlmap --version"
}

# ---------------------------------------------------------------------
# Run installers
# ---------------------------------------------------------------------
echo
install_ysoserial
echo
install_phpggc
echo
install_sqlmap

# ---------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------
echo
info "${BOLD}Install complete.${RESET}  Verifying everything's on PATH..."
for tool in ysoserial phpggc sqlmap; do
    if command -v "$tool" >/dev/null 2>&1; then
        ok "${tool}  ($(command -v "$tool"))"
    else
        err "${tool} NOT on PATH (re-source your shell or check ${PREFIX})"
    fi
done

echo
info "${BOLD}Next steps:${RESET}"
echo "  1. Set up free local-server tunneling for client-side payload"
echo "     delivery. See ${BOLD}docs/bscp-checklist.md${RESET}."
echo "  2. Read ${BOLD}docs/bscp-checklist.md${RESET} for a 'when to reach for"
echo "     which tool' reference card."
echo "  3. Use ${BOLD}exploit_server.py${RESET} from this repo to host your"
echo "     XSS / CSRF / file payloads with auto-tunneling support."
