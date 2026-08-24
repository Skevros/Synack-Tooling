#!/usr/bin/env bash
set -euo pipefail

echo "[+] Checking connectivity..."
curl -sf https://github.com > /dev/null && echo "  github.com OK" || echo "  github.com FAILED"
curl -sf https://go.dev > /dev/null && echo "  go.dev OK" || echo "  go.dev FAILED"

echo "[+] Fixing apt sources to HTTPS (if archive.ubuntu.com fails on 80)..."
sudo sed -i 's|http://archive.ubuntu.com|https://archive.ubuntu.com|g; s|http://security.ubuntu.com|https://security.ubuntu.com|g' /etc/apt/sources.list 2>/dev/null || true
sudo apt update -qq || echo "  apt update failed, continuing anyway"

echo "[+] Native tools via apt..."
sudo apt install -y git curl wget jq tmux ripgrep python3 python3-pip nmap 2>&1 | tail -5

echo "[+] Installing Go directly (bypassing apt/archive.ubuntu.com)..."
GO_VERSION="1.23.4"   # check go.dev/dl for current
if ! command -v go &>/dev/null; then
  curl -LO "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
  sudo tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
  rm "go${GO_VERSION}.linux-amd64.tar.gz"
fi
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
grep -qxF 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' ~/.bashrc || \
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc

echo "[+] Bypassing Go module proxy (not allowlisted)..."
export GOPROXY=direct
export GOSUMDB=off
grep -qxF 'export GOPROXY=direct' ~/.bashrc || echo 'export GOPROXY=direct' >> ~/.bashrc
grep -qxF 'export GOSUMDB=off' ~/.bashrc || echo 'export GOSUMDB=off' >> ~/.bashrc

echo "[+] Installing Go-based tools..."
while read -r pkg; do
  [ -z "$pkg" ] && continue
  echo "  installing $pkg"
  go install "$pkg" || echo "  FAILED: $pkg"
done < go-tools.txt

echo "[+] Pulling wordlists..."
[ -d ~/wordlists ] || git clone --depth 1 https://github.com/assetnote/wordlists.git ~/wordlists

echo "[+] Done. Install Burp CE manually from portswigger.net (GUI installer)."

echo "[+] Installing bbot..."
if ! command -v pipx &>/dev/null; then
  sudo apt install -y pipx 2>&1 | tail -3
  pipx ensurepath
  export PATH="$PATH:$HOME/.local/bin"
  grep -qxF 'export PATH=$PATH:$HOME/.local/bin' ~/.bashrc || \
    echo 'export PATH=$PATH:$HOME/.local/bin' >> ~/.bashrc
fi
pipx install bbot || pip install bbot --user
