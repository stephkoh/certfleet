#!/usr/bin/env bash
# ============================================================================
# certfleet ADM Agent (Linux / famille Red Hat - dnf)
# Pousse une fiche serveur + alertes logs vers certfleet, et exécute les
# commandes APPROUVÉES (file de commandes validée par un admin).
# Communication : HTTPS sortant uniquement (push + poll). Aucun port entrant.
# Config : /etc/certfleet-agent/agent.conf  (CERTFLEET_URL, ENROLL_TOKEN)
# ============================================================================
set -uo pipefail
AGENT_VERSION="1.2.1"
CONF="${CERTFLEET_AGENT_CONF:-/etc/certfleet-agent/agent.conf}"
STATE_DIR="/var/lib/certfleet-agent"
TOKEN_FILE="$STATE_DIR/token"
ID_FILE="$STATE_DIR/agent_id"
LAST_LOG_FILE="$STATE_DIR/last_log_ts"
mkdir -p "$STATE_DIR" 2>/dev/null

[ -f "$CONF" ] && . "$CONF"
: "${CERTFLEET_URL:?CERTFLEET_URL manquant dans $CONF}"
: "${ENROLL_TOKEN:=}"
ALLOW_SHELL="${ALLOW_SHELL:-0}"
SUDO_MODE="${SUDO_MODE:-nopasswd}"
AUTO_UPDATE="${AUTO_UPDATE:-1}"

# ---- Auto-mise à jour de l'agent depuis certfleet (HTTPS sortant) ----
self_update(){
  [ "$AUTO_UPDATE" = "1" ] || return 0
  local self="/usr/local/bin/certfleet-agent"
  [ -w "$self" ] || return 0   # nécessite que le binaire soit modifiable par le compte de service
  curl -fsSL -m 20 "$CERTFLEET_URL/api/adm/agent.sh" -o /tmp/.bagent_new 2>/dev/null || { rm -f /tmp/.bagent_new; return 0; }
  if [ -s /tmp/.bagent_new ] && head -1 /tmp/.bagent_new | grep -q '^#!' && bash -n /tmp/.bagent_new 2>/dev/null; then
    if ! cmp -s /tmp/.bagent_new "$self"; then
      cat /tmp/.bagent_new > "$self" 2>/dev/null && echo "[agent] auto-mise à jour appliquée"
      rm -f /tmp/.bagent_new
      exec "$self" "${1:-run}"   # ré-exécute la nouvelle version
    fi
  fi
  rm -f /tmp/.bagent_new
}

# agent_id stable (basé sur machine-id)
if [ ! -f "$ID_FILE" ]; then
  mid="$(cat /etc/machine-id 2>/dev/null || hostname)"
  echo "$(hostname -s)-${mid:0:12}" > "$ID_FILE"
fi
AGENT_ID="$(cat "$ID_FILE")"

jq_get(){ python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))" 2>/dev/null; }
json_escape(){ python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))'; }

curl_json(){ curl -fsS -m 30 -H "Content-Type: application/json" -H "X-Agent-Token: $(cat "$TOKEN_FILE" 2>/dev/null)" "$@"; }

KEY_PRIV="$STATE_DIR/agent_key.pem"

# Génère la paire de clés RSA de l'agent si absente (clé privée locale, jamais transmise)
ensure_key(){
  if [ ! -s "$KEY_PRIV" ]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEY_PRIV" 2>/dev/null
    chmod 600 "$KEY_PRIV"
  fi
}

# ---- Enrôlement (obtient un token agent ; envoie la clé PUBLIQUE) ----
enroll(){
  ensure_key
  local pubkey; pubkey="$(openssl pkey -in "$KEY_PRIV" -pubout 2>/dev/null)"
  local os_id os_ver
  os_id="$(. /etc/os-release 2>/dev/null; echo "${NAME:-Linux}")"
  os_ver="$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-}")"
  local body
  body="$(ENROLL_TOKEN="$ENROLL_TOKEN" AGENT_ID="$AGENT_ID" HN="$(hostname -s)" \
    FQDN="$(hostname -f 2>/dev/null || hostname)" IP="$(hostname -I 2>/dev/null | awk '{print $1}')" \
    OS="$os_id" OSV="$os_ver" KERNEL="$(uname -r)" ARCH="$(uname -m)" AGENT_VER="$AGENT_VERSION" PUBKEY="$pubkey" SUDO_MODE="$SUDO_MODE" \
    python3 <<'PY'
import json, os
print(json.dumps({
 "enroll_token":os.environ.get("ENROLL_TOKEN"),"agent_id":os.environ.get("AGENT_ID"),
 "hostname":os.environ.get("HN"),"fqdn":os.environ.get("FQDN"),"ip":os.environ.get("IP"),
 "os":os.environ.get("OS"),"os_version":os.environ.get("OSV"),"kernel":os.environ.get("KERNEL"),
 "arch":os.environ.get("ARCH"),"agent_version":os.environ.get("AGENT_VER"),"pubkey":os.environ.get("PUBKEY"),
 "sudo_mode":os.environ.get("SUDO_MODE"),
}))
PY
)"
  local resp; resp="$(curl -fsS -m 30 -H "Content-Type: application/json" -d "$body" "$CERTFLEET_URL/api/adm/enroll")" || { echo "[agent] enroll échec"; return 1; }
  local tok; tok="$(echo "$resp" | jq_get token)"
  [ -n "$tok" ] && { echo "$tok" > "$TOKEN_FILE"; chmod 600 "$TOKEN_FILE"; echo "[agent] enrôlé OK"; } || { echo "[agent] pas de token"; return 1; }
}

# ---- Détection du rôle ----
detect_role(){
  local svcs="$1"
  case "$svcs" in
    *kubelet*|*k3s*|*rke2*|*k0s*|*kube-*) echo "kubernetes" ;;
    *viewagent*|*vmware-view*|*horizon*|*vmwblusbd*|*standalone-agent*) echo "horizon-vdi" ;;
    *gdm*|*sddm*|*lightdm*|*gnome-shell*|*plasma*|*xorg*|*wayland*) echo "ordinateur" ;;
    *nginx*|*httpd*|*apache*) echo "web" ;;
    *postgresql*|*mariadb*|*mysqld*|*mongod*) echo "database" ;;
    *docker*|*containerd*|*podman*) echo "container" ;;
    *named*|*bind*) echo "dns" ;;
    *haproxy*|*keepalived*) echo "loadbalancer" ;;
    *redis*|*memcached*) echo "cache" ;;
    *nfs*|*smb*|*ganesha*) echo "storage" ;;
    *postfix*|*dovecot*) echo "mail" ;;
    *) echo "generic" ;;
  esac
}

# ---- Collecte des CVE de sécurité via dnf updateinfo (avis officiels, throttle 1h) ----
CVE_FILE="$STATE_DIR/cves.txt"; CVE_TS_FILE="$STATE_DIR/last_cve_ts"; UPD_FILE_S="$STATE_DIR/updates.txt"
collect_cves(){
  local now last; now="$(date +%s)"; last="$(cat "$CVE_TS_FILE" 2>/dev/null || echo 0)"
  if [ ! -f "$CVE_FILE" ] || [ ! -f "$UPD_FILE_S" ] || [ $((now-last)) -ge 3600 ]; then
    LC_ALL=C timeout 120 dnf -q updateinfo list cves --security 2>/dev/null > "$CVE_FILE.tmp" && mv "$CVE_FILE.tmp" "$CVE_FILE" || rm -f "$CVE_FILE.tmp"
    LC_ALL=C timeout 120 dnf -q list --upgrades 2>/dev/null > "$UPD_FILE_S.tmp" && mv "$UPD_FILE_S.tmp" "$UPD_FILE_S" || rm -f "$UPD_FILE_S.tmp"
    echo "$now" > "$CVE_TS_FILE"
  fi
}

# ---- Collecte des connexions TCP établies (service graph, throttle 5 min) ----
CONN_FILE_S="$STATE_DIR/conns.txt"; CONN_TS_FILE="$STATE_DIR/last_conn_ts"; CONN_PENDING="$STATE_DIR/conns.pending"
collect_conns(){
  local now last; now="$(date +%s)"; last="$(cat "$CONN_TS_FILE" 2>/dev/null || echo 0)"
  if [ $((now-last)) -ge 300 ]; then
    ss -tnH state established 2>/dev/null | awk '{print $(NF-1)" "$NF}' | sort | uniq -c | sort -rn | head -200 > "$CONN_FILE_S"
    echo "$now" > "$CONN_TS_FILE"; : > "$CONN_PENDING"
  fi
}

# ---- Construit la fiche + alertes + report ----
report(){
  [ -s "$TOKEN_FILE" ] || enroll || return 1
  local services ports role since connfile=""
  collect_cves
  collect_conns
  [ -f "$CONN_PENDING" ] && connfile="$CONN_FILE_S"
  services="$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | awk '{print $1}' | sed 's/\.service$//' | head -60 | paste -sd, -)"
  ports="$(ss -tlnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un | head -60 | paste -sd, -)"
  role="$(detect_role "$services")"
  rpm -qa --qf '%{NAME}|%{VERSION}-%{RELEASE}\n' 2>/dev/null | sort | head -1500 > /tmp/.bp_pkgs
  since="$(cat "$LAST_LOG_FILE" 2>/dev/null || echo '1 hour ago')"
  journalctl --since "$since" -p err --no-pager -o cat 2>/dev/null | grep -viE 'audit|sudo:.*COMMAND' | sort | uniq -c | sort -rn | head -20 > /tmp/.bp_alerts
  date '+%Y-%m-%d %H:%M:%S' > "$LAST_LOG_FILE"

  AGENT_ID="$AGENT_ID" ROLE="$role" SERVICES="$services" PORTS="$ports" AGENT_VER="$AGENT_VERSION" CVE_FILE="$CVE_FILE" UPD_FILE="$UPD_FILE_S" CONN_FILE="$connfile" \
  python3 <<'PY' > /tmp/.certfleet_report.json
import json, os, subprocess
def osrel():
    d={}
    try:
        for l in open('/etc/os-release'):
            if '=' in l:
                k,v=l.strip().split('=',1); d[k]=v.strip('"')
    except Exception: pass
    return d
def sh(c):
    # timeout dur : un montage NFS mort ou une commande pendue ne doit jamais bloquer le report
    try:
        r=subprocess.run(c,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,universal_newlines=True,timeout=15)
        return (r.stdout or "").rstrip("\n")
    except Exception: return ""
o=osrel()
pkgs=[]
try:
    for line in open('/tmp/.bp_pkgs'):
        line=line.strip()
        if '|' in line:
            n,v=line.split('|',1); pkgs.append({"name":n,"version":v})
except Exception: pass
alerts=[]
try:
    for line in open('/tmp/.bp_alerts'):
        line=line.strip()
        if not line: continue
        parts=line.split(None,1)
        cnt=parts[0] if parts and parts[0].isdigit() else "1"
        msg=parts[1] if len(parts)>1 else line
        alerts.append({"severity":"error","source":"journald","message":("x%s : %s"%(cnt,msg))[:500]})
except Exception: pass
cves=[]
try:
    cf=os.environ.get("CVE_FILE")
    if cf and os.path.exists(cf):
        seen=set(); ARCHS=('.x86_64','.noarch','.i686','.aarch64','.src')
        for line in open(cf):
            line=line.strip()
            if not line.upper().startswith("CVE-"): continue
            parts=line.split()
            if len(parts)<2: continue
            cve=parts[0]; nvra=parts[-1]            # le paquet est le DERNIER token (robuste FR/EN)
            if not nvra.endswith(ARCHS): continue   # garde-fou : c'est bien un NVRA, pas une sévérité
            mid=' '.join(parts[1:-1]).lower()       # sévérité = tokens du milieu (locale-agnostique)
            if 'crit' in mid: sev='Critical'
            elif 'import' in mid: sev='Important'
            elif 'moder' in mid or 'modér' in mid: sev='Moderate'
            elif 'low' in mid or 'faible' in mid or 'bas' in mid: sev='Low'
            else: sev=''
            for arch in ARCHS:
                if nvra.endswith(arch): nvra=nvra[:-len(arch)]; break
            seg=nvra.rsplit('-',2)
            key=(cve,seg[0])
            if key in seen: continue
            seen.add(key)
            cves.append({"cve":cve,"package":seg[0],"fixed_version":('-'.join(seg[1:]) if len(seg)>=3 else ''),"severity":sev})
except Exception: pass
updates=[]
try:
    uf=os.environ.get("UPD_FILE")
    if uf and os.path.exists(uf):
        ARCHS=('.x86_64','.noarch','.i686','.aarch64','.src')
        for line in open(uf):
            parts=line.split()
            if len(parts)<3: continue
            na=parts[0]
            if not na.endswith(ARCHS): continue
            name=na[:na.rfind('.')]
            if not name: continue
            updates.append({"package":name,"version":parts[1],"repo":parts[2]})
            if len(updates)>=200: break
except Exception: pass
conns=[]
try:
    cnf=os.environ.get("CONN_FILE")
    if cnf and os.path.exists(cnf):
        def ipport(s):
            s=s.strip()
            if s.startswith('['):  # IPv6 [addr]:port
                h,_,p=s[1:].partition(']:'); return h,p
            i=s.rfind(':'); return (s[:i],s[i+1:]) if i>0 else (s,'')
        def norm(ip): return ip[7:] if ip.startswith('::ffff:') else ip
        for line in open(cnf):
            parts=line.split()
            if len(parts)<3: continue
            occ=int(parts[0]) if parts[0].isdigit() else 1
            lip,lport=ipport(parts[1]); rip,rport=ipport(parts[2])
            lip=norm(lip); rip=norm(rip)
            if not rip or rip.startswith('127.') or rip in ('::1','0.0.0.0'): continue
            if rip.startswith('::'): continue  # ignorer IPv6 pur
            conns.append({"local_ip":lip,"local_port":int(lport) if lport.isdigit() else None,"remote_ip":rip,"remote_port":int(rport) if rport.isdigit() else None,"protocol":"tcp","occurrence":occ})
except Exception: pass
logins=[]
try:
    WD={'Mon','Tue','Wed','Thu','Fri','Sat','Sun'}
    for line in sh("last -w -n 60 2>/dev/null").splitlines():
        line=line.rstrip()
        if not line or line.split()[0] in ('reboot','wtmp','shutdown'): continue
        parts=line.split()
        if len(parts)<4: continue
        user=parts[0]; tty=parts[1]
        if len(parts)>2 and parts[2] in WD:
            frm='local'; rest=' '.join(parts[2:])
        else:
            frm=parts[2]; rest=' '.join(parts[3:])
        logins.append({"user":user,"tty":tty,"from":frm,"when":rest[:60]})
        if len(logins)>=10: break
except Exception: pass
# ── Sessions ouvertes EN CE MOMENT (who) ──
sessions=[]
try:
    for line in sh("who 2>/dev/null").splitlines():
        p=line.split(None,4)
        if not p or not p[0]: continue
        frm=p[4].strip("()") if len(p)>4 else ""
        sessions.append({"user":p[0],"tty":p[1] if len(p)>1 else "","since":(p[2]+" "+p[3]) if len(p)>3 else (p[2] if len(p)>2 else ""),"from":frm})
        if len(sessions)>=40: break
except Exception: pass
# ── Sécurité & conformité ──
def _grepv(path,key):
    try:
        for l in open(path):
            s=l.strip()
            if s.lower().startswith(key.lower()):
                p=s.split(None,1); return p[1] if len(p)>1 else ''
    except Exception: pass
    return ''
def _grp(*gs):
    m=set()
    for g in gs:
        for line in sh("getent group %s 2>/dev/null"%g).splitlines():
            p=line.split(':')
            if len(p)>=4 and p[3]: m.update(x for x in p[3].split(',') if x)
    return sorted(m)
def _active(s): return sh("systemctl is-active %s 2>/dev/null"%s)=="active"
def _catf(p):
    try: return open(p).read().strip()
    except Exception: return ''
security={
 "ssh_root_login":_grepv('/etc/ssh/sshd_config','PermitRootLogin') or '(defaut)',
 "pass_max_days":_grepv('/etc/login.defs','PASS_MAX_DAYS'),
 "sudo_users":_grp('wheel','sudo')[:25],
 "shell_users":[l.split(':')[0] for l in sh("getent passwd").splitlines() if l.split(':')[-1].rstrip().endswith(('bash','/sh','zsh'))][:30],
 "fail2ban":"active" if _active('fail2ban') else "inactif",
 "antivirus":[s for s in ('clamd@scan','clamav-daemon','falcon-sensor','wazuh-agent','sophos-spl') if _active(s)],
}
# ── Matériel & inventaire ──
hardware={
 "vendor":_catf('/sys/class/dmi/id/sys_vendor'),"product":_catf('/sys/class/dmi/id/product_name'),
 "serial":_catf('/sys/class/dmi/id/product_serial') or _catf('/etc/certfleet-agent/serial'),
 "bios":_catf('/sys/class/dmi/id/bios_version'),
 "bios_date":_catf('/sys/class/dmi/id/bios_date'),
 "cpu_model":next((l.split(':',1)[1].strip() for l in sh("cat /proc/cpuinfo").splitlines() if l.lower().startswith('model name')),''),
}
_dock=sh("docker ps --format '{{.Names}} ({{.Image}})' 2>/dev/null")
if _dock and 'denied' not in _dock.lower() and 'cannot' not in _dock.lower():
    hardware["containers"]=[c for c in _dock.splitlines() if c][:30]
disk_lines=[l for l in sh("df -hlP -x tmpfs -x devtmpfs 2>/dev/null").splitlines()[1:] if l][:8]  # -l = FS locaux only (un NFS mort fige df)
# ── Alertes seuils (disque / charge / mémoire / uptime) ──
for l in disk_lines:
    for c in l.split():
        if c.endswith('%'):
            try:
                pct=int(c[:-1])
                if pct>=85: alerts.append({"severity":("error" if pct>=95 else "warning"),"source":"disk","message":("Disque a %d%% : %s"%(pct,l))[:200]})
            except Exception: pass
            break
try:
    la=float(sh("cat /proc/loadavg").split()[0]); nc=int(sh("nproc") or 1)
    if la>nc*2: alerts.append({"severity":"warning","source":"load","message":"Charge CPU elevee : %.2f pour %d coeurs"%(la,nc)})
except Exception: pass
try:
    for l in sh("free").splitlines():
        if l.startswith('Mem:'):
            p=l.split(); mp=int(float(p[2])/float(p[1])*100)
            if mp>=90: alerts.append({"severity":"warning","source":"mem","message":"Memoire utilisee a %d%%"%mp})
            break
except Exception: pass
try:
    days=float(sh("cat /proc/uptime").split()[0])/86400
    if days>180: alerts.append({"severity":"info","source":"uptime","message":"Serveur non redemarre depuis %d jours (kernel potentiellement non patche)"%int(days)})
except Exception: pass
ip=sh("hostname -I").split()
fiche={
 "hostname":sh("hostname -s"),"fqdn":sh("hostname -f"),
 "ip":ip[0] if ip else None,
 "os":o.get("NAME","Linux"),"os_version":o.get("VERSION_ID",""),"pretty":o.get("PRETTY_NAME",""),
 "kernel":sh("uname -r"),"arch":sh("uname -m"),"uptime":sh("uptime -p"),
 "cpu":sh("nproc"),"mem_total_kb":sh("awk '/MemTotal/{print $2}' /proc/meminfo"),
 "services":[s for s in os.environ.get("SERVICES","").split(',') if s],
 "ports":[p for p in os.environ.get("PORTS","").split(',') if p],
 "packages":pkgs,"package_count":len(pkgs),"agent_version":os.environ.get("AGENT_VER",""),
 "recent_logins":logins,"sessions":sessions,"security":security,"hardware":hardware,
 "updates":updates,"updates_count":len(updates),
 "load_avg":sh("cat /proc/loadavg 2>/dev/null").split(' ')[:3],
 "disk":disk_lines,
 "mem_used_pct":sh("free 2>/dev/null | awk '/Mem:/{printf \"%d\", $3/$2*100}'"),
 "selinux":sh("getenforce 2>/dev/null"),
 "firewall":sh("systemctl is-active firewalld 2>/dev/null"),
 "failed_units":[l.split()[0] for l in sh("systemctl list-units --state=failed --no-legend 2>/dev/null").splitlines() if l][:10],
 "ntp_sync":sh("timedatectl show -p NTPSynchronized --value 2>/dev/null"),
}
print(json.dumps({"agent_id":os.environ.get("AGENT_ID"),"role":os.environ.get("ROLE"),"fiche":fiche,"alerts":alerts,"cves":cves,"connections":conns}))
PY
  if curl_json -X POST -d @/tmp/.certfleet_report.json "$CERTFLEET_URL/api/adm/report" >/dev/null; then
    echo "[agent] report OK (role=$role)"; [ -n "$connfile" ] && rm -f "$CONN_PENDING"
  else echo "[agent] report échec"; fi
  rm -f /tmp/.certfleet_report.json /tmp/.bp_pkgs /tmp/.bp_alerts
}

# ---- Exécute une commande approuvée (allowlist par 'kind') ----
# Sécurité : le nom de package/service est strictement validé (anti-injection) et toujours quoté.
valid_name(){ printf '%s' "$1" | grep -qE '^[A-Za-z0-9][A-Za-z0-9._+-]{0,128}$'; }
report_result(){ # id rc out
  local body; body="$(python3 -c 'import json,sys;print(json.dumps({"agent_id":sys.argv[1],"command_id":int(sys.argv[2]),"exit_code":int(sys.argv[3]),"result":sys.argv[4][:9000]}))' "$AGENT_ID" "$1" "$2" "$3")"
  curl_json -X POST -d "$body" "$CERTFLEET_URL/api/adm/command-result" >/dev/null
  echo "[agent] commande #$1 rc=$2"
}
# Remonte une alerte immédiate à certfleet (panneau Alertes logs)
send_alert(){ # severity source message
  local body; body="$(python3 -c 'import json,sys;print(json.dumps({"agent_id":sys.argv[1],"alerts":[{"severity":sys.argv[2],"source":sys.argv[3],"message":sys.argv[4][:1000]}]}))' "$AGENT_ID" "$1" "$2" "$3" 2>/dev/null)"
  [ -n "$body" ] && curl_json -X POST -d "$body" "$CERTFLEET_URL/api/adm/report" >/dev/null 2>&1
}
# Après une MAJ : redémarre les services qui en ont besoin et vérifie qu'ils repartent (rc=1 si échec)
post_update_restart(){
  local svcs out="" failed=""
  # On EXCLUT les sessions utilisateur (user@/session/getty) et le coeur systemd : dangereux à redémarrer.
  svcs="$(feed | sudo -S -p '' /usr/bin/dnf needs-restarting -s 2>/dev/null | awk '{print $1}' | grep -E '\.service$' \
    | grep -vE '^(user@|user-|session-|getty@|serial-getty@|systemd-|dbus|polkit|init|certfleet-agent)' | sort -u | head -12)"
  [ -z "$svcs" ] && { echo "Aucun service applicatif à redémarrer (sessions utilisateur & coeur systemd exclus)."; return 0; }
  while IFS= read -r svc; do
    [ -z "$svc" ] && continue
    systemctl is-active --quiet "$svc" 2>/dev/null || continue
    feed | timeout 40 sudo -S -p '' /usr/bin/systemctl restart "$svc" >/dev/null 2>&1
    sleep 1
    if systemctl is-active --quiet "$svc" 2>/dev/null; then out="$out
  ✓ $svc (actif)"; else out="$out
  ✗ $svc EN ÉCHEC"; failed="$failed $svc"; fi
  done <<EOF
$svcs
EOF
  echo "Services redémarrés/vérifiés (hors sessions utilisateur) :$out"
  [ -n "$failed" ] && return 1
  return 0
}
run_command(){
  local id="$1" kind="$2" action="$3" pkg="$4" enc="$5" pb="$6"
  local out rc pw=""
  # Déchiffre le mot de passe sudo (chiffré par certfleet avec la clé publique de l'agent)
  if [ -n "$enc" ]; then
    pw="$(printf '%s' "$enc" | base64 -d 2>/dev/null | openssl pkeyutl -decrypt -inkey "$KEY_PRIV" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 2>/dev/null)"
    [ -z "$pw" ] && { report_result "$id" 1 "Échec déchiffrement du mot de passe sudo"; return; }
  fi
  feed(){ [ -n "$pw" ] && printf '%s\n' "$pw"; return 0; }
  case "$kind" in
    dnf_update)
      if [ -z "$pkg" ]; then out="package requis"; rc=1;
      elif ! valid_name "$pkg"; then out="nom de package invalide (refusé) : $pkg"; rc=1;
      else
        out="$(feed | sudo -S -p '' /usr/bin/dnf -y update -- "$pkg" 2>&1)"; rc=$?
        if [ "$rc" -eq 0 ]; then
          rm -f "$CVE_TS_FILE" "$CVE_FILE" "$UPD_FILE_S"   # force re-collecte CVE/paquets -> retire le package mis à jour
          local rr rrc; rr="$(post_update_restart)"; rrc=$?
          out="$out

=== Contrôle redémarrage des services ===
$rr"
          if [ "$rrc" -ne 0 ]; then rc=1; send_alert "critical" "post-update" "MAJ $pkg : service(s) en échec après redémarrage :$(printf '%s' "$rr" | grep 'ÉCHEC' | tr '\n' ' ')"; fi
        fi
      fi ;;
    dnf_upgrade)  out="$(feed | sudo -S -p '' /usr/bin/dnf -y upgrade 2>&1)"; rc=$?; [ "$rc" -eq 0 ] && rm -f "$CVE_TS_FILE" "$CVE_FILE" "$UPD_FILE_S" ;;
    pkg_version)  if valid_name "$pkg"; then out="$(rpm -q -- "$pkg" 2>&1)"; rc=$?; else out="nom invalide"; rc=1; fi ;;
    os_release)   out="$(cat /etc/os-release 2>&1)"; rc=$? ;;
    service_restart)
      if valid_name "$pkg"; then out="$(feed | sudo -S -p '' /usr/bin/systemctl restart -- "$pkg" 2>&1; systemctl is-active -- "$pkg")"; rc=$?;
      else out="nom de service invalide (refusé)"; rc=1; fi ;;
    shell)        if [ "$ALLOW_SHELL" = "1" ]; then out="$(bash -c "$action" 2>&1 | tail -60)"; rc=$?; else out="shell désactivé (ALLOW_SHELL=0)"; rc=1; fi ;;
    cert)
      # Déploiement de certificat (certfleet). payload chiffré hybride :
      #   aeskey_enc = RSA-OAEP(clé AES 32o, pubkey agent) ; key_cipher = AES-256-CBC(clé privée PEM)
      # cert_pem (fullchain) est public. Écriture via helper sudo si présent, sinon directe (bac-à-sable).
      if ! command -v openssl >/dev/null 2>&1; then out="openssl absent"; rc=1;
      else
        local td cp kp iv rl akhex chp
        td="$(mktemp -d 2>/dev/null)"
        if [ -z "$td" ]; then out="mktemp KO"; rc=1;
        else
          local perr aerr
          printf '%s' "$pb" | base64 -d > "$td/payload.json" 2>/dev/null
          perr="$(python3 -c 'import json,sys,base64,os
d=json.load(open(sys.argv[2])); td=sys.argv[1]
open(os.path.join(td,"cert.pem"),"w").write(d.get("cert_pem",""))
open(os.path.join(td,"chain.pem"),"w").write(d.get("chain_pem",""))
open(os.path.join(td,"aeskey.bin"),"wb").write(base64.b64decode(d.get("aeskey_enc","") or ""))
open(os.path.join(td,"key.bin"),"wb").write(base64.b64decode(d.get("key_cipher","") or ""))
open(os.path.join(td,"meta"),"w").write("\n".join([d.get("cert_path",""),d.get("key_path",""),d.get("key_iv",""),d.get("reload_cmd",""),d.get("chain_path","")]))' "$td" "$td/payload.json" 2>&1)"
          cp="$(sed -n 1p "$td/meta" 2>/dev/null)"; kp="$(sed -n 2p "$td/meta" 2>/dev/null)"
          iv="$(sed -n 3p "$td/meta" 2>/dev/null)"; rl="$(sed -n 4p "$td/meta" 2>/dev/null)"
          chp="$(sed -n 5p "$td/meta" 2>/dev/null)"
          akhex="$(openssl pkeyutl -decrypt -inkey "$KEY_PRIV" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in "$td/aeskey.bin" 2>/tmp/.certaerr | od -An -v -tx1 | tr -d ' \n')"
          aerr="$(head -2 /tmp/.certaerr 2>/dev/null | tr '\n' ' ')"; rm -f /tmp/.certaerr
          if [ ! -f "$td/meta" ]; then out="cert: parse KO | pb_len=${#pb} json_len=$(wc -c <"$td/payload.json" 2>/dev/null) head=[$(head -c 60 "$td/payload.json" 2>/dev/null | tr -d '\n')] err=$perr"; rc=1;
          elif [ -z "$cp" ] || [ -z "$kp" ]; then out="cert: chemins manquants (cert_path/key_path) — payload incomplet"; rc=1;
          elif [ -z "$akhex" ]; then out="cert: RSA-OAEP KO (aeskey.bin=$(wc -c <"$td/aeskey.bin" 2>/dev/null)o, pubkey<->clé agent ?) $aerr"; rc=1;
          elif ! openssl enc -d -aes-256-cbc -K "$akhex" -iv "$iv" -in "$td/key.bin" -out "$td/key.pem" 2>/dev/null || ! grep -q "PRIVATE KEY" "$td/key.pem" 2>/dev/null; then
            out="cert: déchiffrement clé privée (AES) KO"; rc=1;
          else
            # PEM combiné (HAProxy) : cert_path == key_path → un seul fichier fullchain+clé
            local sc="$td/cert.pem" sk="$td/key.pem"
            if [ "$cp" = "$kp" ]; then cat "$td/cert.pem" "$td/key.pem" > "$td/combined.pem"; sc="$td/combined.pem"; sk="$td/combined.pem"; fi
            if [ -x /usr/local/bin/certfleet-cert-install ]; then
              # Chaine intermediaire : ecrite par un PREMIER appel qui n'utilise que le
              # contrat historique a 5 arguments (cert_path=chaine, reload vide). Ainsi
              # AUCUNE mise a jour du helper n'est necessaire sur les hotes deja equipes.
              # La cle est reecrite a l'identique au passage : sans effet, mais ca satisfait
              # la validation du helper qui exige une cle valide en 4e argument.
              local outc="" rcc=0
              if [ -n "$chp" ]; then
                outc="$(feed | sudo -S -p '' /usr/local/bin/certfleet-cert-install "$chp" "$kp" "$td/chain.pem" "$td/key.pem" "" 2>&1)"; rcc=$?
                [ $rcc -ne 0 ] && outc="chaine KO ($chp) : $outc"
              fi
              # Puis le certificat, la cle et le reload.
              out="$(feed | sudo -S -p '' /usr/local/bin/certfleet-cert-install "$cp" "$kp" "$sc" "$sk" "$rl" 2>&1)"; rc=$?
              if [ -n "$chp" ]; then
                out="$out | chaine: $([ $rcc -eq 0 ] && echo "OK ($chp)" || echo "$outc")"
                [ $rcc -ne 0 ] && rc=1
              fi
            else
              mkdir -p "$(dirname "$cp")" "$(dirname "$kp")" 2>/dev/null
              if cp -f "$sc" "$cp" 2>/dev/null && cp -f "$sk" "$kp" 2>/dev/null; then
                chmod 600 "$kp" 2>/dev/null; [ "$cp" != "$kp" ] && chmod 644 "$cp" 2>/dev/null
                if [ -n "$chp" ]; then mkdir -p "$(dirname "$chp")" 2>/dev/null
                  cp -f "$td/chain.pem" "$chp" 2>/dev/null && chmod 644 "$chp" 2>/dev/null; fi
                out="OK (écriture directe, sans helper sudo) cert=$cp clé=$kp sha256_clé=$(sha256sum "$kp" 2>/dev/null | cut -d' ' -f1)"
                [ -n "$rl" ] && out="$out | reload NON exécuté (helper sudo requis pour /etc)"
                rc=0
              else out="cert: échec écriture (droits ? installe le helper /usr/local/bin/certfleet-cert-install pour /etc) cible=$cp"; rc=1; fi
            fi
          fi
          rm -rf "$td"
        fi
      fi ;;
    *)            out="kind inconnu (refusé): $kind"; rc=1 ;;
  esac
  pw=""
  report_result "$id" "$rc" "$out"
}

poll(){
  [ -s "$TOKEN_FILE" ] || return 0
  local cmds; cmds="$(curl_json "$CERTFLEET_URL/api/adm/commands?agent_id=$AGENT_ID&token=$(cat "$TOKEN_FILE")")" || return 0
  # Séparateur = Unit Separator (0x1f), PAS une tabulation : les champs vides
  # (pkg/enc pour une commande cert) doivent être préservés (read collapse les
  # tabs consécutifs car tab = IFS whitespace → décalait les champs).
  echo "$cmds" | python3 -c 'import json,sys,base64
for c in json.load(sys.stdin):
    p=c.get("payload") or {}
    pb=base64.b64encode(json.dumps(p).encode()).decode()
    print("\x1f".join([str(c["id"]),c.get("kind","shell"),(c.get("action") or "").replace("\x1f"," "),p.get("package",""),p.get("sudo_pw_enc",""),pb]))' 2>/dev/null | while IFS=$'\x1f' read -r id kind action pkg enc pb; do
    [ -n "$id" ] && run_command "$id" "$kind" "$action" "$pkg" "$enc" "$pb"
  done
}

case "${1:-run}" in
  enroll) enroll ;;
  report) report ;;
  poll)   poll ;;
  run)    self_update "run"; report; poll ;;
  selfupdate) self_update "run" ;;
  *) echo "usage: $0 {run|report|poll|enroll}"; exit 1 ;;
esac
