#!/usr/bin/env bash
# ============================================================================
# certfleet — agent Linux / BSD
#
# Installé sur chaque serveur cible. Il fait trois choses, et rien d'autre :
#   1. s'enrôler auprès du hub, en générant localement sa paire de clés RSA ;
#   2. signaler qu'il est vivant, avec son identité machine ;
#   3. venir chercher les certificats à poser, les déchiffrer, les écrire et
#      recharger le service.
#
# Communication SORTANTE uniquement, en HTTPS. Aucun port à ouvrir en entrée.
# Le hub n'ouvre jamais de connexion vers ce serveur et ne détient aucun
# identifiant sur lui.
#
# La clé privée du certificat arrive chiffrée et n'est déchiffrable QUE par cet
# agent : le hub chiffre avec la clé publique que l'agent a générée ici, et ne
# possède pas la clé privée correspondante.
#
# Config   : /etc/certfleet-agent/agent.conf   (CERTFLEET_URL, ENROLL_TOKEN)
# État     : /var/lib/certfleet-agent          (identifiant, jeton, clé RSA)
# Requiert : bash, curl, openssl, python3
# ============================================================================
set -uo pipefail

AGENT_VERSION="2.0.0"
CONF="${CERTFLEET_AGENT_CONF:-/etc/certfleet-agent/agent.conf}"
STATE_DIR="/var/lib/certfleet-agent"
TOKEN_FILE="$STATE_DIR/token"
ID_FILE="$STATE_DIR/agent_id"
KEY_PRIV="$STATE_DIR/agent_key.pem"
HELPER="/usr/local/bin/certfleet-cert-install"

mkdir -p "$STATE_DIR" 2>/dev/null
chmod 700 "$STATE_DIR" 2>/dev/null

[ -f "$CONF" ] && . "$CONF"
: "${CERTFLEET_URL:?CERTFLEET_URL manquant dans $CONF}"
: "${ENROLL_TOKEN:=}"
CERTFLEET_URL="${CERTFLEET_URL%/}"

# Mot de passe sudo, utile seulement si le compte de service n'est pas NOPASSWD.
SUDO_MODE="${SUDO_MODE:-nopasswd}"
SUDO_PW="${SUDO_PW:-}"
AUTO_UPDATE="${AUTO_UPDATE:-1}"

log(){ echo "[agent] $*"; }
die(){ echo "[agent] $*" >&2; exit 1; }

for bin in curl openssl python3; do
  command -v "$bin" >/dev/null 2>&1 || die "$bin est requis mais absent"
done

# ── Identité stable ─────────────────────────────────────────────────────────
# Dérivée de machine-id : elle survit à un changement de nom d'hôte, ce qui
# évite de créer un doublon dans l'inventaire du hub.
if [ ! -f "$ID_FILE" ]; then
  mid="$(cat /etc/machine-id 2>/dev/null || hostname)"
  echo "$(hostname -s 2>/dev/null || hostname)-${mid:0:12}" > "$ID_FILE"
fi
AGENT_ID="$(cat "$ID_FILE")"

curl_json(){
  curl -fsS -m 30 -H "Content-Type: application/json" \
       -H "X-Agent-Token: $(cat "$TOKEN_FILE" 2>/dev/null)" "$@"
}

# Alimente le mot de passe sudo sur l'entrée standard, ou rien en NOPASSWD.
feed(){ [ "$SUDO_MODE" = "nopasswd" ] && printf '' || printf '%s\n' "$SUDO_PW"; }

# ── Clé de l'agent ──────────────────────────────────────────────────────────
# Générée ici, elle ne quitte jamais la machine. Seule la partie publique part
# vers le hub, à l'enrôlement.
ensure_key(){
  if [ ! -s "$KEY_PRIV" ]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEY_PRIV" 2>/dev/null \
      || die "génération de la clé RSA impossible"
    chmod 600 "$KEY_PRIV"
    log "paire de clés RSA générée"
  fi
}

# ── Identité machine, envoyée au hub ────────────────────────────────────────
machine_json(){
  python3 - "$AGENT_ID" "$AGENT_VERSION" "$SUDO_MODE" <<'PY'
import json, platform, socket, sys

def os_release(key):
    try:
        for line in open("/etc/os-release"):
            k, _, v = line.partition("=")
            if k == key:
                return v.strip().strip('"')
    except Exception:
        pass
    return ""

# Adresse par laquelle la machine sort : plus parlante que la liste complète
# des interfaces. Aucun paquet n'est réellement émis (UDP non connecté).
ip = ""
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("192.0.2.1", 9))          # réseau réservé à la documentation
    ip = s.getsockname()[0]
    s.close()
except Exception:
    pass

print(json.dumps({
    "agent_id":      sys.argv[1],
    "agent_version": sys.argv[2],
    "sudo_mode":     sys.argv[3],
    "platform":      "linux",
    "hostname":      socket.gethostname().split(".")[0],
    "fqdn":          socket.getfqdn(),
    "ip":            ip,
    "os":            os_release("NAME") or platform.system(),
    "os_version":    os_release("VERSION_ID"),
    "kernel":        platform.release(),
    "arch":          platform.machine(),
}))
PY
}

# ── Enrôlement ──────────────────────────────────────────────────────────────
enroll(){
  [ -n "$ENROLL_TOKEN" ] || die "ENROLL_TOKEN manquant dans $CONF"
  ensure_key

  local pub body resp token
  pub="$(openssl pkey -in "$KEY_PRIV" -pubout 2>/dev/null)"
  [ -n "$pub" ] || die "extraction de la clé publique impossible"

  body="$(machine_json | ENROLL_TOKEN="$ENROLL_TOKEN" AGENT_PUBKEY="$pub" python3 -c 'import json,sys,os
d = json.load(sys.stdin)
d["enroll_token"] = os.environ["ENROLL_TOKEN"]
d["pubkey"] = os.environ["AGENT_PUBKEY"]
print(json.dumps(d))' 2>/dev/null)" || die "construction de la requête impossible"

  resp="$(curl -fsS -m 30 -H "Content-Type: application/json" \
               -d "$body" "$CERTFLEET_URL/api/agents/enroll" 2>&1)" \
    || die "enrôlement refusé : $resp"

  token="$(printf '%s' "$resp" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("token",""))' 2>/dev/null)"
  [ -n "$token" ] || die "le hub n'a pas renvoyé de jeton : $resp"

  printf '%s' "$token" > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
  log "enrôlé auprès de $CERTFLEET_URL sous l'identifiant $AGENT_ID"
}

# ── Signal de vie ───────────────────────────────────────────────────────────
heartbeat(){
  [ -s "$TOKEN_FILE" ] || { log "pas encore enrôlé"; return 0; }
  if curl_json -X POST -d "$(machine_json)" \
       "$CERTFLEET_URL/api/agents/heartbeat" >/dev/null 2>&1; then
    log "signal de vie transmis"
  else
    log "signal de vie : hub injoignable"
  fi
}

# ── Mise à jour automatique ─────────────────────────────────────────────────
# Le script n'est remplacé que s'il est syntaxiquement valide : une version
# tronquée par une coupure réseau ne doit pas casser l'agent en place.
self_update(){
  [ "$AUTO_UPDATE" = "1" ] || return 0
  local self="/usr/local/bin/certfleet-agent"
  [ -w "$self" ] || return 0
  curl -fsSL -m 20 "$CERTFLEET_URL/api/agents/agent.sh" -o /tmp/.cf_agent_new 2>/dev/null \
    || { rm -f /tmp/.cf_agent_new; return 0; }
  if [ -s /tmp/.cf_agent_new ] && head -1 /tmp/.cf_agent_new | grep -q '^#!' \
     && bash -n /tmp/.cf_agent_new 2>/dev/null && ! cmp -s /tmp/.cf_agent_new "$self"; then
    cat /tmp/.cf_agent_new > "$self" 2>/dev/null && log "mise à jour appliquée"
    rm -f /tmp/.cf_agent_new
    exec "$self" "${1:-run}"
  fi
  rm -f /tmp/.cf_agent_new
}

# ── Compte rendu d'exécution ────────────────────────────────────────────────
report_result(){   # id code sortie
  local body
  body="$(python3 -c 'import json,sys
print(json.dumps({"agent_id":sys.argv[1],"command_id":int(sys.argv[2]),
                  "exit_code":int(sys.argv[3]),"result":sys.argv[4][:9000]}))' \
        "$AGENT_ID" "$1" "$2" "$3")"
  curl_json -X POST -d "$body" "$CERTFLEET_URL/api/agents/command-result" >/dev/null 2>&1
  log "commande #$1 terminée (code $2)"
}

# ── Pose dans un keystore Java ──────────────────────────────────────────────
# Un keystore n'est pas un fichier de certificat : on y remplace une entrée
# identifiée par son alias. La manœuvre se fait en deux temps, car keytool ne
# sait pas importer une clé privée seule — il faut passer par un PKCS#12.
#
# Le keystore est réécrit en place, après sauvegarde : une application qui
# redémarre pendant l'opération doit retrouver un fichier valide.
deploy_keystore(){   # td params_json
  local td="$1" pj="$2"
  local ks alias storepass restart

  ks="$(printf '%s' "$pj" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("keystore_path",""))' 2>/dev/null)"
  alias="$(printf '%s' "$pj" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("alias",""))' 2>/dev/null)"
  storepass="$(printf '%s' "$pj" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("storepass",""))' 2>/dev/null)"
  restart="$(printf '%s' "$pj" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("restart_cmd",""))' 2>/dev/null)"

  command -v keytool >/dev/null 2>&1 || { echo "keytool absent : installez un JDK ou un JRE"; return 1; }
  [ -n "$ks" ] || { echo "keystore_path manquant"; return 1; }
  [ -n "$alias" ] || { echo "alias manquant"; return 1; }
  [ -n "$storepass" ] || { echo "mot de passe du keystore manquant (champ storepass de la cible)"; return 1; }

  # Mot de passe temporaire du PKCS#12 intermédiaire : il ne quitte pas ce
  # répertoire, détruit en fin de commande.
  local p12pass; p12pass="$(openssl rand -base64 24)"

  if ! openssl pkcs12 -export -in "$td/cert.pem" -inkey "$td/key.pem" \
         -name "$alias" -out "$td/bundle.p12" -passout "pass:$p12pass" 2>"$td/err"; then
    echo "construction du PKCS#12 impossible : $(head -2 "$td/err" | tr '\n' ' ')"; return 1
  fi

  # Sauvegarde datée : en cas d'échec de l'import, l'ancien keystore est intact
  # et restaurable, y compris si keytool a laissé un fichier à moitié écrit.
  local bak=""
  if [ -f "$ks" ]; then
    bak="$ks.certfleet-$(date +%Y%m%d%H%M%S)"
    cp -p "$ks" "$bak" 2>/dev/null || { echo "sauvegarde de $ks impossible (droits ?)"; return 1; }
    # L'alias existant doit partir : keytool refuse d'écraser une entrée.
    keytool -delete -alias "$alias" -keystore "$ks" -storepass "$storepass" >/dev/null 2>&1
  fi

  if ! keytool -importkeystore -noprompt \
        -srckeystore "$td/bundle.p12" -srcstoretype PKCS12 -srcstorepass "$p12pass" \
        -destkeystore "$ks" -deststoretype PKCS12 -deststorepass "$storepass" \
        -srcalias "$alias" -destalias "$alias" >"$td/kt" 2>&1; then
    local msg; msg="$(tail -3 "$td/kt" | tr '\n' ' ')"
    [ -n "$bak" ] && cp -p "$bak" "$ks" 2>/dev/null && msg="$msg | keystore restauré depuis la sauvegarde"
    echo "import dans le keystore en échec : $msg"; return 1
  fi

  local out="alias « $alias » remplacé dans $ks"
  [ -n "$bak" ] && out="$out | sauvegarde : $bak"

  if [ -n "$restart" ]; then
    local r rc2
    if [ -x "$HELPER" ]; then
      # Le helper valide la commande contre sa liste blanche ; l'agent ne
      # décide jamais seul de redémarrer un service.
      r="$(feed | sudo -S -p '' "$HELPER" "$ks" "$ks" "$ks" "$ks" "$restart" 2>&1)"; rc2=$?
    else
      r="$(sh -c "$restart" 2>&1)"; rc2=$?
    fi
    out="$out | redémarrage : $([ $rc2 -eq 0 ] && echo OK || echo "ÉCHEC — $r")"
    [ $rc2 -ne 0 ] && { echo "$out"; return 1; }
  else
    out="$out | AUCUN redémarrage demandé : l'application garde l'ancien certificat en mémoire jusqu'à son prochain démarrage"
  fi

  echo "$out"
  return 0
}

# ── Pose d'un certificat ────────────────────────────────────────────────────
# Le payload est chiffré en hybride :
#   aeskey_enc = RSA-OAEP(clé AES 32 o, clé publique de CET agent)
#   key_cipher = AES-256-CBC(clé privée PEM)
# Le certificat complet (fullchain) est public et voyage en clair.
deploy_cert(){   # id payload_base64
  local id="$1" pb="$2" out="" rc=0

  local td; td="$(mktemp -d 2>/dev/null)"
  [ -n "$td" ] || { report_result "$id" 1 "mktemp impossible"; return; }

  printf '%s' "$pb" | base64 -d > "$td/payload.json" 2>/dev/null

  local perr
  perr="$(python3 -c 'import json,sys,base64,os
d = json.load(open(sys.argv[2])); td = sys.argv[1]
open(os.path.join(td,"cert.pem"),"w").write(d.get("cert_pem",""))
open(os.path.join(td,"chain.pem"),"w").write(d.get("chain_pem",""))
open(os.path.join(td,"aeskey.bin"),"wb").write(base64.b64decode(d.get("aeskey_enc","") or ""))
open(os.path.join(td,"key.bin"),"wb").write(base64.b64decode(d.get("key_cipher","") or ""))
open(os.path.join(td,"secrets.bin"),"wb").write(base64.b64decode(d.get("secrets_cipher","") or ""))
open(os.path.join(td,"meta"),"w").write("\n".join([
    d.get("cert_path",""), d.get("key_path",""), d.get("key_iv",""),
    d.get("reload_cmd",""), d.get("chain_path",""),
    d.get("mode","file"), d.get("target_type",""), d.get("secrets_iv","")]))
open(os.path.join(td,"params.json"),"w").write(json.dumps(d.get("params") or {}))' "$td" "$td/payload.json" 2>&1)"

  local cp kp iv rl chp mode ttype pj
  cp="$(sed -n 1p "$td/meta" 2>/dev/null)";  kp="$(sed -n 2p "$td/meta" 2>/dev/null)"
  iv="$(sed -n 3p "$td/meta" 2>/dev/null)";  rl="$(sed -n 4p "$td/meta" 2>/dev/null)"
  chp="$(sed -n 5p "$td/meta" 2>/dev/null)"
  mode="$(sed -n 6p "$td/meta" 2>/dev/null)"; ttype="$(sed -n 7p "$td/meta" 2>/dev/null)"
  pj="$(cat "$td/params.json" 2>/dev/null)"
  local siv; siv="$(sed -n 8p "$td/meta" 2>/dev/null)"

  # Déchiffrement de la clé AES avec la clé privée de l'agent.
  local akhex aerr
  akhex="$(openssl pkeyutl -decrypt -inkey "$KEY_PRIV" \
             -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
             -pkeyopt rsa_mgf1_md:sha256 -in "$td/aeskey.bin" 2>/tmp/.cf_aerr \
           | od -An -v -tx1 | tr -d ' \n')"
  aerr="$(head -2 /tmp/.cf_aerr 2>/dev/null | tr '\n' ' ')"; rm -f /tmp/.cf_aerr

  if [ ! -f "$td/meta" ]; then
    out="payload illisible : $perr"; rc=1
  elif [ "$mode" != "store" ] && { [ -z "$cp" ] || [ -z "$kp" ]; }; then
    out="chemins manquants dans le payload (cert_path / key_path)"; rc=1
  elif [ -z "$akhex" ]; then
    out="déchiffrement RSA-OAEP impossible — la clé publique connue du hub ne correspond pas à celle de cet agent. Réenrôlez-le. $aerr"; rc=1
  elif ! openssl enc -d -aes-256-cbc -K "$akhex" -iv "$iv" -in "$td/key.bin" \
           -out "$td/key.pem" 2>/dev/null || ! grep -q "PRIVATE KEY" "$td/key.pem" 2>/dev/null; then
    out="déchiffrement de la clé privée impossible"; rc=1
  elif [ "$mode" = "store" ]; then
    # Les paramètres sensibles voyagent chiffrés avec la même clé AES que la
    # clé privée : ils ne sont donc lisibles que par cet agent, et n'ont jamais
    # transité en clair dans la file de commandes du hub.
    if [ -n "$siv" ] && [ -s "$td/secrets.bin" ]; then
      if openssl enc -d -aes-256-cbc -K "$akhex" -iv "$siv" \
           -in "$td/secrets.bin" -out "$td/secrets.json" 2>/dev/null; then
        pj="$(printf '%s' "$pj" | python3 -c 'import json,sys
p = json.load(sys.stdin)
p.update(json.load(open(sys.argv[1])))
print(json.dumps(p))' "$td/secrets.json" 2>/dev/null)"
      else
        log "déchiffrement des paramètres sensibles impossible"
      fi
    fi
    case "$ttype" in
      java_keystore) out="$(deploy_keystore "$td" "$pj" 2>&1)"; rc=$? ;;
      *) out="type « $ttype » en mode magasin : non pris en charge par l'agent Linux"; rc=1 ;;
    esac
  else
    # HAProxy attend un seul fichier contenant le certificat ET la clé : le hub
    # le signale en donnant le même chemin pour les deux.
    local sc="$td/cert.pem" sk="$td/key.pem"
    if [ "$cp" = "$kp" ]; then
      cat "$td/cert.pem" "$td/key.pem" > "$td/combined.pem"
      sc="$td/combined.pem"; sk="$td/combined.pem"
    fi

    if [ -x "$HELPER" ]; then
      # La chaîne intermédiaire passe par un PREMIER appel qui n'utilise que le
      # contrat historique à 5 arguments : aucune mise à jour du helper n'est
      # nécessaire sur les hôtes déjà équipés. La clé est réécrite à l'identique
      # au passage — sans effet, mais le helper exige une clé valide en 4ᵉ argument.
      local outc="" rcc=0
      if [ -n "$chp" ]; then
        outc="$(feed | sudo -S -p '' "$HELPER" "$chp" "$kp" "$td/chain.pem" "$td/key.pem" "" 2>&1)"; rcc=$?
        [ $rcc -ne 0 ] && outc="chaîne en échec ($chp) : $outc"
      fi
      out="$(feed | sudo -S -p '' "$HELPER" "$cp" "$kp" "$sc" "$sk" "$rl" 2>&1)"; rc=$?
      if [ -n "$chp" ]; then
        out="$out | chaîne : $([ $rcc -eq 0 ] && echo "OK ($chp)" || echo "$outc")"
        [ $rcc -ne 0 ] && rc=1
      fi
    else
      # Sans le helper, on ne peut ni écrire dans /etc ni recharger un service :
      # on le dit clairement plutôt que de laisser croire au succès.
      mkdir -p "$(dirname "$cp")" "$(dirname "$kp")" 2>/dev/null
      if cp -f "$sc" "$cp" 2>/dev/null && cp -f "$sk" "$kp" 2>/dev/null; then
        chmod 600 "$kp" 2>/dev/null
        [ "$cp" != "$kp" ] && chmod 644 "$cp" 2>/dev/null
        if [ -n "$chp" ]; then
          mkdir -p "$(dirname "$chp")" 2>/dev/null
          cp -f "$td/chain.pem" "$chp" 2>/dev/null && chmod 644 "$chp" 2>/dev/null
        fi
        out="écrit sans helper sudo — cert=$cp clé=$kp"
        [ -n "$rl" ] && out="$out | RECHARGEMENT NON EXÉCUTÉ : installez $HELPER"
        rc=0
      else
        out="écriture refusée sur $cp — installez le helper $HELPER"; rc=1
      fi
    fi
  fi

  rm -rf "$td"
  report_result "$id" "$rc" "$out"
}

# ── File de commandes ───────────────────────────────────────────────────────
# Un agent certfleet n'exécute qu'un seul type de commande : poser un
# certificat. Tout le reste est refusé, même si le hub le demandait.
poll(){
  [ -s "$TOKEN_FILE" ] || return 0
  local cmds
  cmds="$(curl_json "$CERTFLEET_URL/api/agents/commands?agent_id=$AGENT_ID&token=$(cat "$TOKEN_FILE")")" || return 0

  # Séparateur = Unit Separator (0x1f) et non une tabulation : les champs vides
  # doivent être préservés, or read agrège les tabulations consécutives.
  echo "$cmds" | python3 -c 'import json,sys,base64
for c in json.load(sys.stdin):
    p = c.get("payload") or {}
    print("\x1f".join([str(c["id"]), c.get("kind","?"),
                       base64.b64encode(json.dumps(p).encode()).decode()]))' 2>/dev/null \
  | while IFS=$'\x1f' read -r id kind pb; do
      [ -n "$id" ] || continue
      case "$kind" in
        cert) deploy_cert "$id" "$pb" ;;
        *)    report_result "$id" 1 "type de commande refusé par l'agent : $kind" ;;
      esac
    done
}

# ── Installation du déclencheur périodique ──────────────────────────────────
install_timer(){
  if ! command -v systemctl >/dev/null 2>&1; then
    log "systemd absent — ajoutez une entrée cron sur « $0 run »"
    return 0
  fi

  cat > /etc/systemd/system/certfleet-agent.service <<'UNIT'
[Unit]
Description=Agent certfleet — dépose les certificats et recharge les services
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/certfleet-agent run
UNIT

  cat > /etc/systemd/system/certfleet-agent.timer <<'UNIT'
[Unit]
Description=Interroge le hub certfleet toutes les 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
# Décale le déclenchement de 0 à 60 s : sans cela, tout un parc interrogerait
# le hub à la même seconde.
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
UNIT

  systemctl daemon-reload
  if systemctl enable --now certfleet-agent.timer >/dev/null 2>&1; then
    log "minuterie systemd active — interrogation toutes les 5 minutes"
  else
    log "activation de la minuterie systemd en échec"
  fi
}

case "${1:-run}" in
  enroll)  enroll ;;
  beat)    heartbeat ;;
  poll)    ensure_key; poll ;;
  install) install_timer ;;
  run)     self_update "run"; ensure_key; heartbeat; poll ;;
  version) echo "certfleet-agent $AGENT_VERSION" ;;
  *)       echo "usage: $0 {run|enroll|beat|poll|install|version}"; exit 1 ;;
esac
