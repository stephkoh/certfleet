#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# test/api.sh — test d'intégration contre une vraie base PostgreSQL.
#
# Monte une base jetable dans Docker, démarre le serveur, exerce l'API
# (authentification, cloisonnement des rôles, annuaire, agents, audit),
# puis nettoie tout.
#
#   bash test/api.sh          ou      npm run test:api
#
# Exige : docker, node, curl, openssl.
# ═══════════════════════════════════════════════════════════════════
set -u
cd "$(dirname "$0")/.."

DB=certfleet-testdb
DBPORT=55432
PORT=18080
B="http://127.0.0.1:$PORT"
ADMIN_PW="MotDePasseTest1234"

pass=0; fail=0
ok(){ printf '  ok   %s\n' "$1"; pass=$((pass+1)); }
ko(){ printf '  FAIL %s -> %s\n' "$1" "$2"; fail=$((fail+1)); }
code(){ curl -s -o /dev/null -w '%{http_code}' "$@"; }
# Extraction JSON par node : jq n'est pas garanti présent.
jget(){ node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const v=process.argv[1].split(".").reduce((o,k)=>o&&o[k],JSON.parse(s));console.log(v==null?"":v)}catch{console.log("")}})' "$1"; }

cleanup(){
  [ -f .test.pid ] && kill "$(cat .test.pid)" 2>/dev/null
  rm -f .test.pid .test.log
  docker rm -f "$DB" >/dev/null 2>&1
}
trap cleanup EXIT

echo "── base de test ──"
docker rm -f "$DB" >/dev/null 2>&1
docker run -d --name "$DB" -e POSTGRES_PASSWORD=test -e POSTGRES_DB=certfleet \
  -p "$DBPORT:5432" postgres:16-alpine >/dev/null || { echo "docker indisponible"; exit 1; }
for i in $(seq 1 40); do
  docker exec "$DB" pg_isready -U postgres -q 2>/dev/null && break
  sleep 1
done
echo "  PostgreSQL prêt"

echo "── démarrage du serveur ──"
export DATABASE_URL="postgres://postgres:test@127.0.0.1:$DBPORT/certfleet"
export ADMIN_TOKEN="$(openssl rand -hex 32)"
export CERT_VAULT_KEY="$(openssl rand -base64 32)"
export BOOTSTRAP_PASSWORD="$ADMIN_PW"
export COOKIE_SECURE=false PORT="$PORT"
export MONITOR_INTERVAL_MIN=1440 RENEW_INTERVAL_MIN=1440

node src/server.js > .test.log 2>&1 &
echo $! > .test.pid
for i in $(seq 1 30); do
  curl -sf "$B/healthz" >/dev/null 2>&1 && break
  kill -0 "$(cat .test.pid)" 2>/dev/null || { echo "  le serveur s'est arrêté :"; cat .test.log; exit 1; }
  sleep 1
done
echo "  serveur en écoute"

echo "── authentification ──"
[ "$(code "$B/healthz")" = 200 ] && ok "/healthz" || ko "/healthz" "injoignable"
c=$(code "$B/api/certificates/overview"); [ "$c" = 401 ] && ok "API fermée sans jeton" || ko "API fermée sans jeton" "$c"
c=$(code -X POST -H 'Content-Type: application/json' -d '{"username":"admin","password":"faux"}' "$B/api/login")
[ "$c" = 401 ] && ok "mot de passe faux refusé" || ko "mot de passe faux" "$c"

TOK=$(curl -s -X POST -H 'Content-Type: application/json' \
      -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" "$B/api/login" | jget token)
[ -n "$TOK" ] && ok "connexion administrateur" || ko "connexion administrateur" "aucun jeton"
A="Authorization: Bearer $TOK"
curl -s -H "$A" "$B/api/me" | grep -q '"role":"admin"' && ok "/api/me : rôle admin" || ko "/api/me" "rôle inattendu"

echo "── module certificats ──"
[ "$(code -H "$A" "$B/api/certificates/target-types")" = 200 ] && ok "types de cible" || ko "types de cible" "erreur"
[ "$(code -H "$A" "$B/api/certificates/overview")" = 200 ] && ok "vue d'ensemble" || ko "vue d'ensemble" "erreur"
[ "$(code -H "$A" "$B/api/certificates/")" = 200 ] && ok "inventaire" || ko "inventaire" "erreur"

echo "── comptes ──"
[ "$(code -H "$A" "$B/api/users/")" = 200 ] && ok "liste des comptes" || ko "liste des comptes" "erreur"
r=$(curl -s -H "$A" -H 'Content-Type: application/json' -X POST \
    -d "{\"username\":\"lecteur\",\"password\":\"$ADMIN_PW\",\"role\":\"viewer\"}" "$B/api/users/")
echo "$r" | grep -q '"role":"viewer"' && ok "création d'un compte viewer" || ko "création viewer" "$r"
c=$(code -H "$A" -H 'Content-Type: application/json' -X POST \
    -d '{"username":"faible","password":"court","role":"viewer"}' "$B/api/users/")
[ "$c" = 400 ] && ok "mot de passe trop court refusé" || ko "mot de passe trop court" "$c"
c=$(code -H "$A" -H 'Content-Type: application/json' -X POST \
    -d "{\"username\":\"lecteur\",\"password\":\"$ADMIN_PW\"}" "$B/api/users/")
[ "$c" = 409 ] && ok "identifiant en double refusé" || ko "identifiant en double" "$c"

echo "── cloisonnement des rôles ──"
r=$(curl -s -X POST -H 'Content-Type: application/json' \
    -d "{\"username\":\"lecteur\",\"password\":\"$ADMIN_PW\"}" "$B/api/login")
VT=$(printf '%s' "$r" | jget token)
V="Authorization: Bearer $VT"
[ -n "$VT" ] && ok "connexion du compte viewer" || ko "connexion viewer" "$r"
echo "$r" | grep -q '"must_change_password":true' && ok "changement de mot de passe imposé" || ko "must_change_password" "absent"
[ "$(code -H "$V" "$B/api/certificates/overview")" = 200 ] && ok "viewer : lecture autorisée" || ko "viewer lecture" "refusée"
c=$(code -H "$V" -H 'Content-Type: application/json' -X POST -d '{"common_name":"x.exemple.fr"}' "$B/api/certificates/")
[ "$c" = 403 ] && ok "viewer : écriture refusée" || ko "viewer écriture" "$c"
[ "$(code -H "$V" "$B/api/users/")" = 403 ] && ok "viewer : administration refusée" || ko "viewer administration" "autorisée"

AID=$(curl -s -H "$A" "$B/api/users/" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const u=JSON.parse(s).users.find(x=>x.username==="admin");console.log(u?u.id:"")})')
c=$(code -H "$A" -H 'Content-Type: application/json' -X PUT -d '{"role":"viewer"}' "$B/api/users/$AID")
[ "$c" = 409 ] && ok "dernier administrateur non rétrogradable" || ko "dernier administrateur" "$c"

echo "── annuaire ──"
[ "$(code -H "$A" "$B/api/users/ldap/config")" = 200 ] && ok "configuration lisible" || ko "configuration" "erreur"
curl -s -H "$A" "$B/api/users/ldap/config" | grep -q '"bind_password"' \
  && ko "mot de passe de bind exposé" "fuite" || ok "mot de passe de bind jamais renvoyé"
r=$(curl -s -H "$A" -H 'Content-Type: application/json' -X PUT \
    -d '{"enabled":true,"url":"ldaps://dc.exemple.local:636","base_dn":"DC=exemple,DC=local","bind_dn":"svc@exemple.local","bind_password":"SECRET-BIND","group_roles":[{"group":"certfleet-admins","role":"admin"}]}' \
    "$B/api/users/ldap/config")
echo "$r" | grep -q '"has_bind_password":true' && ok "mot de passe de bind enregistré" || ko "enregistrement bind" "$r"
echo "$r" | grep -q 'SECRET-BIND' && ko "secret renvoyé par l'API" "fuite" || ok "secret absent de la réponse"
n=$(docker exec "$DB" psql -U postgres -d certfleet -tAc "select count(*) from settings where value::text like '%SECRET-BIND%'")
[ "$n" = "0" ] && ok "secret chiffré en base, jamais en clair" || ko "secret en clair en base" "$n ligne(s)"
curl -s -H "$A" -X POST "$B/api/users/ldap/test" | grep -q '"ok":false' \
  && ok "test annuaire : échec propre sur serveur fictif" || ko "test annuaire" "réponse inattendue"

echo "── agents ──"
[ "$(code "$B/api/agents/agent.sh")" = 200 ] && ok "script d'agent servi" || ko "script d'agent" "absent"
curl -s "$B/api/agents/agent.sh" | bash -n - 2>/dev/null && ok "agent servi syntaxiquement valide" || ko "syntaxe agent" "erreur"
curl -s "$B/api/agents/cert-install.sh" | bash -n - 2>/dev/null && ok "helper servi syntaxiquement valide" || ko "syntaxe helper" "erreur"
c=$(code -X POST -H 'Content-Type: application/json' -d '{"agent_id":"x"}' "$B/api/agents/enroll")
[ "$c" = 503 ] && ok "enrôlement fermé sans jeton configuré" || ko "enrôlement sans jeton" "$c"
docker exec "$DB" psql -U postgres -d certfleet -qtAc \
  "INSERT INTO settings(key,value) VALUES('enroll_token','\"JETON-TEST\"'::jsonb) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value" >/dev/null
c=$(code -X POST -H 'Content-Type: application/json' -d '{"agent_id":"srv1","enroll_token":"FAUX"}' "$B/api/agents/enroll")
[ "$c" = 403 ] && ok "mauvais jeton d'enrôlement refusé" || ko "mauvais jeton" "$c"
AT=$(curl -s -X POST -H 'Content-Type: application/json' \
     -d '{"agent_id":"srv1","enroll_token":"JETON-TEST","hostname":"lb-01","os":"Rocky"}' \
     "$B/api/agents/enroll" | jget token)
[ -n "$AT" ] && ok "enrôlement accepté" || ko "enrôlement" "aucun jeton"
AT2=$(curl -s -X POST -H 'Content-Type: application/json' \
      -d '{"agent_id":"srv1","enroll_token":"JETON-TEST","hostname":"lb-01"}' \
      "$B/api/agents/enroll" | jget token)
[ "$AT" = "$AT2" ] && ok "réenrôlement conserve le jeton" || ko "réenrôlement" "jeton changé"
[ "$(code "$B/api/agents/commands?agent_id=srv1&token=FAUX")" != 200 ] && ok "file protégée par le jeton d'agent" || ko "file protégée" "ouverte"
[ "$(code "$B/api/agents/commands?agent_id=srv1&token=$AT")" = 200 ] && ok "l'agent lit sa file" || ko "lecture de la file" "erreur"
curl -s -H "$A" "$B/api/agents/" | grep -q 'lb-01' && ok "agent visible côté hub" || ko "inventaire agents" "absent"
[ "$(code "$B/api/agents/")" = 401 ] && ok "inventaire des agents authentifié" || ko "inventaire ouvert" "accessible"

echo "── agents : enrolement complet ──"
# L'installateur porte le jeton d'enrolement : il ne doit jamais etre servi
# sans que l'appelant l'ait deja presente.
c=$(code "$B/api/agents/install.sh")
[ "$c" = 403 ] || [ "$c" = 503 ] && ok "installateur jamais servi sans jeton ($c)" || ko "installateur" "$c"
TOKR=$(curl -s -H "$A" -X POST "$B/api/agents/enroll-token/rotate" | jget token)
[ -n "$TOKR" ] && ok "jeton d'enrolement genere depuis l'API" || ko "generation du jeton" "vide"
[ "$(code -H "Authorization: Bearer mauvais" "$B/api/agents/install.sh")" = 403 ] && ok "installateur refuse un mauvais jeton" || ko "mauvais jeton" "accepte"

INST=$(curl -s -H "Authorization: Bearer $TOKR" "$B/api/agents/install.sh")
printf '%s' "$INST" | bash -n - 2>/dev/null && ok "installateur Linux syntaxiquement valide" || ko "syntaxe installateur" "erreur"
printf '%s' "$INST" | grep -q "$TOKR" && ok "jeton insere dans l'installateur" || ko "jeton absent" "non insere"
printf '%s' "$INST" | grep -q 'certfleet-agent enroll' && ok "installateur enrole la machine" || ko "enrolement absent" "manquant"
printf '%s' "$INST" | grep -q 'sudoers.d/certfleet-agent' && ok "installateur pose la regle sudoers" || ko "sudoers absent" "manquant"

INSTW=$(curl -s -H "Authorization: Bearer $TOKR" "$B/api/agents/install.ps1")
printf '%s' "$INSTW" | grep -q 'PSVersion.Major -lt 7' && ok "installateur Windows verifie PowerShell 7" || ko "controle PowerShell" "absent"
[ "$(code "$B/api/agents/agent.ps1")" = 200 ] && ok "agent Windows telechargeable" || ko "agent.ps1" "absent"

# Enrolement reel avec une vraie cle RSA, puis signal de vie.
PUBP=$(mktemp); PRIVP=$(mktemp)
openssl genrsa -out "$PRIVP" 2048 2>/dev/null; openssl rsa -in "$PRIVP" -pubout -out "$PUBP" 2>/dev/null
BODY=$(node -e 'const fs=require("fs");console.log(JSON.stringify({agent_id:"win1",enroll_token:process.argv[1],hostname:"srv-iis",platform:"windows",os:"Windows Server",agent_version:"2.0.0",pubkey:fs.readFileSync(process.argv[2],"utf8")}))' "$TOKR" "$PUBP")
AT2=$(curl -s -X POST -H 'Content-Type: application/json' -d "$BODY" "$B/api/agents/enroll" | jget token)
[ -n "$AT2" ] && ok "agent Windows enrole avec sa cle publique" || ko "enrolement Windows" "refuse"

HB=$(code -X POST -H 'Content-Type: application/json' -H "X-Agent-Token: $AT2" -d '{"agent_id":"win1","platform":"windows","os":"Windows Server 2022","ip":"192.0.2.10"}' "$B/api/agents/heartbeat")
[ "$HB" = 200 ] && ok "signal de vie accepte" || ko "signal de vie" "$HB"
HB=$(code -X POST -H 'Content-Type: application/json' -H 'X-Agent-Token: faux' -d '{"agent_id":"win1"}' "$B/api/agents/heartbeat")
[ "$HB" = 403 ] && ok "signal de vie refuse avec un mauvais jeton" || ko "signal de vie non protege" "$HB"
curl -s -H "$A" "$B/api/agents/" | grep -q '"platform":"windows"' && ok "plateforme remontee dans l'inventaire" || ko "plateforme" "absente"

[ "$(code -H "$V" -X POST "$B/api/agents/enroll-token/rotate")" = 403 ] && ok "viewer ne peut pas generer de jeton" || ko "cloisonnement du jeton" "autorise"
[ "$(code -H "$A" -X DELETE "$B/api/agents/enroll-token")" = 200 ] && ok "enrolement desactivable" || ko "desactivation" "echec"

echo "── audit ──"
r=$(curl -s -H "$A" "$B/api/users/audit?limit=100")
echo "$r" | grep -q '"action":"login"' && ok "connexions journalisées" || ko "journal connexions" "absent"
echo "$r" | grep -q '"action":"user.create"' && ok "créations de compte journalisées" || ko "journal créations" "absent"
echo "$r" | grep -q 'SECRET-BIND' && ko "secret présent dans le journal" "fuite" || ok "secret absent du journal"

echo "── déconnexion ──"
curl -s -H "$A" -X POST "$B/api/logout" >/dev/null
[ "$(code -H "$A" "$B/api/me")" = 401 ] && ok "session révoquée après déconnexion" || ko "révocation de session" "toujours valide"

echo
echo "$pass réussis, $fail échoués"
exit $([ "$fail" -eq 0 ] && echo 0 || echo 1)
