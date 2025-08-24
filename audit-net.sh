#!/usr/bin/env bash
# Audit UFW / iptables / nftables / Docker interaction on Ubuntu 22.04/24.04
# Default: short report + smoke test.
# Usage:
#   bash audit-net.sh [--full] [--no-smoke] [--smoke] [--port N]
#     --full     : dump full nftables/iptables rules
#     --no-smoke : skip the smoke test
#     --smoke    : force smoke test (default already does it)
#     --port N   : port for smoke test (default 12345)

set -o pipefail

FULL=0
SMOKE=1     # по умолчанию включён
PORT=12345

while [[ $# -gt 0 ]]; do
  case "$1" in
    --full)       FULL=1 ;;
    --no-smoke)   SMOKE=0 ;;
    --smoke)      SMOKE=1 ;;
    --port)       PORT="${2:-12345}"; shift ;;
    -h|--help)
      sed -n '2,50p' "$0"; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

have() { command -v "$1" >/dev/null 2>&1; }
line() { printf '%s\n' "------------------------------------------------------------"; }
h() { printf '\n### %s\n' "$*"; line; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
ok() { printf 'OK: %s\n' "$*"; }

h "System"
if [[ -r /etc/os-release ]]; then . /etc/os-release; echo "OS: ${PRETTY_NAME}"; fi
echo "Kernel: $(uname -r)"
echo "Hostname: $(hostname)"

h "iptables / ip6tables backend"
if have iptables; then
  IPT_V="$(iptables -V 2>&1)"; echo "iptables: $IPT_V"
  [[ "$IPT_V" == *"(nf_tables)"* ]] && echo "backend: iptables-nft (nf_tables)"
  [[ "$IPT_V" == *"(legacy)"* ]]    && echo "backend: legacy"
  have update-alternatives && { echo; echo "update-alternatives (iptables):"; update-alternatives --display iptables 2>/dev/null || true; }
else
  echo "iptables: not found"
fi
have ip6tables && echo "ip6tables: $(ip6tables -V 2>&1)"

h "nftables"
if have nft; then
  echo "nft: $(nft --version 2>&1)"
  if (( FULL )); then
    echo; nft list ruleset || echo "(no nft ruleset or insufficient perms)"
  else
    echo; echo "Tables in ruleset (first 50 lines):"
    nft list ruleset 2>/dev/null | awk '/^table/ {print NR ": " $0}' | head -n 50 || true
    CNT="$(nft list ruleset 2>/dev/null | wc -l | tr -d ' ')"
    echo "(total lines: ${CNT:-0}; use --full to dump all)"
  fi
else
  echo "nft: not found"
fi

h "UFW status & defaults"
if have ufw; then
  echo "Service: enabled=$(systemctl is-enabled ufw 2>/dev/null || echo "unknown"), active=$(systemctl is-active ufw 2>/dev/null || echo "unknown")"
  ufw --version 2>/dev/null | head -n1
  echo
  # статус
  UFW_STATUS_RAW="$(ufw status verbose 2>&1 || true)"
  echo "$UFW_STATUS_RAW"
  # парсинг дефолтной политики
  UFW_ACTIVE=0
  UFW_IN_DEFAULT=""
  if grep -qi '^Status:\s*active' <<<"$UFW_STATUS_RAW"; then UFW_ACTIVE=1; fi
  UFW_IN_DEFAULT="$(grep -i '^Default:' <<<"$UFW_STATUS_RAW" | sed -E 's/^Default:\s*//I')"
  if (( UFW_ACTIVE )); then
    if grep -qiE '^Default:.*\bdeny[[:space:]]*\(incoming\)' <<<"$UFW_STATUS_RAW"; then
      ok "UFW default incoming = deny"
    else
      warn "UFW default incoming is NOT 'deny' → реальность может не совпасть с ожиданиями"
    fi
  else
    warn "UFW is INACTIVE"
  fi
else
  echo "ufw: not installed"
fi

h "iptables highlights (filter)"
if have iptables; then
  iptables -S 2>/dev/null | grep -Ei 'ufw|docker|DOCKER-USER' || echo "(no UFW/DOCKER rules found in filter)"
  (( FULL )) && { echo; iptables -S || true; }
else
  echo "iptables: not found"
fi

h "iptables highlights (nat)"
if have iptables; then
  iptables -t nat -S 2>/dev/null | grep -E 'DOCKER|PREROUTING|POSTROUTING' || echo "(no docker nat rules found)"
  (( FULL )) && { echo; iptables -t nat -S || true; }
fi

h "Docker ↔ UFW sanity check"
DOCKER_PRESENT=0
DOCKER_NAT=0
DOCKER_USER_HAS_RULES=0
DOCKER_USER_ONLY_RETURN=0

if have iptables; then
  iptables -t nat -S | grep -qE '^-N DOCKER\b' && DOCKER_PRESENT=1
  iptables -t nat -S | grep -qE '^-A PREROUTING .* -j DOCKER\b' && DOCKER_NAT=1
  if iptables -S DOCKER-USER >/dev/null 2>&1; then
    RULES="$(iptables -S DOCKER-USER 2>/dev/null | grep '^-A DOCKER-USER' || true)"
    if [[ -n "$RULES" ]]; then
      DOCKER_USER_HAS_RULES=1
      # если единственное правило — RETURN (практически «пусто»)
      if [[ "$(echo "$RULES" | sed -E 's/\s+/-/g')" =~ ^-A-DOCKER-USER-.*-j-RETURN$ ]] && [[ "$(echo "$RULES" | wc -l | tr -d ' ')" == "1" ]]; then
        DOCKER_USER_ONLY_RETURN=1
      fi
    fi
  fi
fi

if (( DOCKER_PRESENT )); then
  echo "Docker iptables chains: present"
  if (( DOCKER_NAT )); then
    echo "Docker NAT PREROUTING → DOCKER: present (ports likely published)"
  fi
  if (( DOCKER_USER_HAS_RULES )); then
    if (( DOCKER_USER_ONLY_RETURN )); then
      warn "DOCKER-USER chain has only RETURN → published container ports may BYPASS UFW policy. Рекомендуется вешать allow/deny здесь."
    else
      ok "DOCKER-USER has custom rules → UFW/политики вероятнее учитываются для контейнерного трафика"
    fi
  else
    warn "DOCKER-USER chain is empty or missing → контейнерные порты могут обходить UFW. Добавьте свою политику в DOCKER-USER."
    echo "  Пример (whitelist на 443 только с 1.2.3.4; затем drop остального):"
    EXT_IF="$(ip -4 route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
    echo "    iptables -I DOCKER-USER -p tcp --dport 443 -s 1.2.3.4 -j ACCEPT"
    echo "    iptables -A DOCKER-USER -j DROP    # осторожно: может заблокировать всё форвард-движение к контейнерам"
    [[ -n "$EXT_IF" ]] && echo "  External interface (guess): ${EXT_IF}"
  fi
else
  echo "Docker iptables chains: not detected (либо Docker не установлен, либо не активен)"
fi

if (( SMOKE )); then
  h "Smoke test (listening on port ${PORT})"
  IP="$(ip -4 route get 8.8.8.8 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if ($i=="src"){print $(i+1); exit}}')"
  [[ -z "$IP" ]] && IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -z "$IP" ]] && IP="<server_ip>"
  PYBIN="$(command -v python3 || command -v python || true)"
  if [[ -n "$PYBIN" ]]; then
    if ss -ltn | grep -q ":${PORT}\b"; then
      warn "Port ${PORT} is already in use; choose another with --port."
    else
      nohup "$PYBIN" -m http.server "$PORT" >/dev/null 2>&1 &
      SRV_PID=$!
      echo "Started http server (PID $SRV_PID) on 0.0.0.0:${PORT}"
      echo
      echo "Проверьте с ДРУГОГО хоста (ожидание 10м, потом сервер сам выключится):"
      echo "  nc -vz ${IP} ${PORT}      # должно быть закрыто при 'deny incoming'"
      echo "  sudo ufw allow ${PORT}/tcp"
      echo "  nc -vz ${IP} ${PORT}      # теперь open"
      # авто-стоп через 10 мин или по ENTER
      { read -t 600 -r _ </dev/tty 2>/dev/null || true; } &
      WAITER=$!
      wait "$WAITER" 2>/dev/null || true
      kill "$SRV_PID" 2>/dev/null || true
      wait "$SRV_PID" 2>/dev/null || true
      echo "Test server stopped."
    fi
  else
    warn "python3 not found; skip smoke test."
  fi
fi

echo
line
echo "Done."
