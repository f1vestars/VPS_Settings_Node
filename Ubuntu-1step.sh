#!/usr/bin/env bash
set -euo pipefail

say(){ echo -e "\n[*] $*"; }
die(){ echo -e "\n[x] $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Запусти скрипт от root."
export DEBIAN_FRONTEND=noninteractive

# ---------- Пакеты / время / автообновления ----------
apt-get update -y
apt-get -y dist-upgrade
apt-get install -y --no-install-recommends ufw fail2ban rsyslog tzdata chrony unattended-upgrades sudo nftables

sed -i 's#\(Unattended-Upgrade::Automatic-Reboot\).*#\1 "true";#' /etc/apt/apt.conf.d/50unattended-upgrades || true
dpkg-reconfigure -fnoninteractive unattended-upgrades || true
systemctl enable --now chrony || true

# ---------- Вопросы ----------
# --- Имя пользователя: очистка и строгая валидация ---
read -r -p "Имя sudo-пользователя [eramer]: " NEW_USER
NEW_USER="${NEW_USER:-eramer}"

# убираем \r, ведущие/замыкающие пробелы и неразрывные пробелы
NEW_USER="$(printf '%s' "$NEW_USER" | tr -d '\r' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g' | tr -d '\302\240')"
# приводим к нижнему регистру
NEW_USER="$(echo "$NEW_USER" | tr '[:upper:]' '[:lower:]')"
# запрещаем root
if [[ "$NEW_USER" == "root" ]]; then
  die "Нельзя использовать имя 'root'. Укажи другое (например, eramer)."
fi
# только латиница в нижнем регистре, цифры, дефис и подчёркивание; первый символ — буква
if [[ ! "$NEW_USER" =~ ^[a-z][a-z0-9_-]*$ ]]; then
  die "Некорректное имя пользователя: '$NEW_USER'.
Допустимо: латинские строчные буквы, цифры, '-' и '_', первый символ — буква (пример: eramer)."
fi

read -r -p "Порт SSH (1024–65535) [10095]: " SSH_PORT; SSH_PORT="${SSH_PORT:-10095}"
[[ "$SSH_PORT" =~ ^[0-9]+$ ]] && (( SSH_PORT>=1024 && SSH_PORT<=65535 )) || die "Некорректный порт SSH."

read -r -p "Включить админский порт 2222 только с фиксированного IP? [yes/no] [yes]: " ADD_ADMIN; ADD_ADMIN="${ADD_ADMIN:-yes}"
if [[ "$ADD_ADMIN" == "yes" ]]; then
  read -r -p "Белый IP для 2222: " ADMIN_IP
  [[ -n "${ADMIN_IP:-}" ]] || die "IP пуст."
fi

read -r -p "Открыть HTTPS/QUIC (443/tcp и 443/udp)? [yes/no] [yes]: " OPEN_HTTPS; OPEN_HTTPS="${OPEN_HTTPS:-yes}"

read -r -p "Часовой пояс [UTC]: " TIMEZONE; TIMEZONE="${TIMEZONE:-UTC}"
timedatectl set-timezone "$TIMEZONE" || true

echo "Вставь ПУБЛИЧНЫЙ SSH-ключ для ${NEW_USER} (одна строка):"
read -r PUBKEY
PUBKEY="$(echo "$PUBKEY" | tr -d '\r')"
[[ -n "$PUBKEY" ]] || die "Ключ пуст."

# ---------- Пользователь / пароль / ключ ----------
if ! id "$NEW_USER" &>/dev/null; then
  adduser --disabled-password --gecos "" "$NEW_USER"
fi
usermod -aG sudo "$NEW_USER"

while true; do
  echo -n "Задай пароль для ${NEW_USER}: "; read -rs PW1; echo
  echo -n "Повтори пароль: "; read -rs PW2; echo
  [[ "$PW1" == "$PW2" && -n "$PW1" ]] && break || echo "Пароли не совпали/пусты, попробуй ещё раз."
done
echo "${NEW_USER}:${PW1}" | chpasswd

install -d -m 700 -o "$NEW_USER" -g "$NEW_USER" "/home/$NEW_USER/.ssh"
printf '%s\n' "$PUBKEY" > "/home/$NEW_USER/.ssh/authorized_keys"
chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"
chown -R "$NEW_USER:$NEW_USER" "/home/$NEW_USER/.ssh"

# ---------- UFW ----------
# Включаем IPv6 = yes (если строки нет — добавим)
if grep -q '^IPV6=' /etc/default/ufw 2>/dev/null; then
  sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw || true
else
  echo 'IPV6=yes' >> /etc/default/ufw
fi

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed

# SSH: limit на выбранном порту
ufw limit "${SSH_PORT}/tcp" comment "SSH custom port (IPv6)" || true

# админский 2222 только с белого IP (без limit)
if [[ "$ADD_ADMIN" == "yes" ]]; then
  ufw allow from "${ADMIN_IP}" to any port 2222 proto tcp comment "Admin access"
fi

# HTTPS/QUIC при необходимости
if [[ "$OPEN_HTTPS" == "yes" ]]; then
  ufw allow 443/tcp comment "HTTPS"
  ufw allow 443/udp comment "QUIC/HTTP3"
fi

ufw --force enable
ufw status verbose

# ---------- SSH (харденинг + смена порта; ТОЛЬКО ssh.service) ----------
SSHD_CFG="/etc/ssh/sshd_config"

sed -i 's/^[#]*PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CFG"
sed -i 's/^[#]*KbdInteractiveAuthentication.*/KbdInteractiveAuthentication no/' "$SSHD_CFG" || true
sed -i 's/^[#]*PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CFG"
grep -q '^PubkeyAuthentication' "$SSHD_CFG" || echo 'PubkeyAuthentication yes' >> "$SSHD_CFG"

for opt in "MaxAuthTries 4" "LoginGraceTime 20" "ClientAliveInterval 300" "ClientAliveCountMax 2"; do
  k=${opt%% *}
  if grep -q "^$k" "$SSHD_CFG"; then
    sed -i "s/^$k.*/$opt/" "$SSHD_CFG"
  else
    echo "$opt" >> "$SSHD_CFG"
  fi
done

# задаём ТОЛЬКО новый порт
sed -i '/^Port /d' "$SSHD_CFG"
echo "Port $SSH_PORT" >> "$SSHD_CFG"

# /run/sshd и tmpfiles (чтобы не было ошибок при старте и после ребута)
install -d -m 0755 -o root -g root /run/sshd
echo 'd /run/sshd 0755 root root -' > /etc/tmpfiles.d/sshd.conf
systemd-tmpfiles --create

# отключаем socket activation, включаем обычный сервис
systemctl disable --now ssh.socket || true
systemctl mask ssh.socket || true
systemctl enable ssh.service

# проверка конфига и перезапуск
sshd -t || die "Ошибка синтаксиса в sshd_config"
systemctl restart ssh.service

# убеждаемся, что слушает нужный порт
ss -ltnp | grep -q ":${SSH_PORT}\b" || die "sshd не слушает порт ${SSH_PORT}"

# ---------- Fail2Ban ----------
install -d /etc/fail2ban/jail.d

# дефолты
cat >/etc/fail2ban/jail.d/00-defaults.local <<'EOF'
[DEFAULT]
banaction = nftables
banaction_allports = nftables[type=allports]
backend = systemd
bantime = 1h
findtime = 10m
maxretry = 3
EOF

# sshd jail на новом порту
cat >/etc/fail2ban/jail.d/10-sshd.local <<EOF
[sshd]
enabled   = true
port      = $SSH_PORT
backend   = systemd
logpath   = /var/log/auth.log
maxretry  = 4
findtime  = 600
bantime   = 600
mode      = aggressive
EOF

# recidive
cat >/etc/fail2ban/jail.d/20-recidive.local <<'EOF'
[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
backend  = auto
bantime  = 1w
findtime = 1d
maxretry = 5
EOF

# Доп. фильтры
if [ ! -f /etc/fail2ban/filter.d/tls-handshake.conf ]; then
  cat >/etc/fail2ban/filter.d/tls-handshake.conf <<'EOF'
[Definition]
failregex = .* tls: TLS handshake failed.*
ignoreregex =
EOF
fi
cat >/etc/fail2ban/jail.d/30-tls-handshake.local <<'EOF'
[tls-handshake]
enabled  = true
port     = https
logpath  = /var/log/syslog
maxretry = 5
bantime  = 3600
EOF

if [ ! -f /etc/fail2ban/filter.d/iperf3.conf ]; then
  cat >/etc/fail2ban/filter.d/iperf3.conf <<'EOF'
[Definition]
failregex = .*iperf3.*(bad auth|unauthorized|refused).*
ignoreregex =
EOF
fi
cat >/etc/fail2ban/jail.d/30-iperf3.local <<'EOF'
[iperf3]
enabled  = true
port     = 5201
logpath  = /var/log/syslog
maxretry = 5
bantime  = 3600
EOF

# Условные jails
have_svc(){ systemctl list-unit-files | grep -q "^$1.service"; }

if have_svc nginx; then
  cat >/etc/fail2ban/jail.d/40-nginx.local <<'EOF'
[nginx-http-auth]
enabled = true
port    = http,https
logpath = /var/log/nginx/error.log

[nginx-botsearch]
enabled = true
port    = http,https
logpath = /var/log/nginx/error.log

[nginx-bad-request]
enabled = true
port    = http,https
logpath = /var/log/nginx/access.log
EOF
fi

if have_svc apache2; then
  cat >/etc/fail2ban/jail.d/40-apache.local <<'EOF'
[apache-auth]
enabled = true
port    = http,https
logpath = /var/log/apache2/error.log

[apache-badbots]
enabled = true
port    = http,https
logpath = /var/log/apache2/access.log
bantime = 48h
maxretry = 1

[apache-noscript]
enabled = true
port    = http,https
logpath = /var/log/apache2/error.log

[apache-overflows]
enabled = true
port    = http,https
logpath = /var/log/apache2/error.log
maxretry = 2
EOF
fi

# явное переопределение порта (поверх чужих файлов)
cat >/etc/fail2ban/jail.d/zz-override-sshd-port.local <<EOF
[sshd]
port = $SSH_PORT
EOF

systemctl enable --now fail2ban
systemctl restart fail2ban || true

# ---------- Финал ----------
say "ГОТОВО. Проверь вход новой сессией (НЕ закрывай текущую):"
echo "  ssh -p $SSH_PORT ${NEW_USER}@<SERVER_IP>"
echo
say "UFW:"
ufw status numbered || true
say "Fail2Ban:"
fail2ban-client status || true
