# certfleet

**Déploie vos certificats ACME là où cert-manager ne va pas.**

Let's Encrypt émet le certificat. `cert-manager` le gère très bien *dans* Kubernetes.
Mais qui le pose sur votre Serv-U, votre HAProxy ALOHA, votre Exchange, votre F5 ?

certfleet fait exactement ça : il émet via ACME, puis **installe le certificat sur des
serveurs qui ne sont pas des conteneurs**, recharge le service, et vérifie ensuite en
rouvrant une vraie connexion TLS que c'est bien le nouveau certificat qui est servi.

> **Pourquoi maintenant.** La durée de vie maximale des certificats passe à 200 jours
> depuis mars 2026, 100 jours en mars 2027, puis **47 jours en 2029**. La validation de
> domaine, elle, ne sera plus réutilisable que 10 jours. Ce qu'on renouvelle aujourd'hui
> une fois par an devra l'être huit fois. Le renouvellement manuel ne tiendra pas.

---

## Ce qu'il fait

**Émission ACME** — client RFC 8555 écrit à la main, sans dépendance externe. Challenge
DNS-01, compte ES256, CSR généré en interne. Fournisseur DNS enfichable (Gandi fourni).

**Déploiement multi-cibles** — nginx, Apache, HAProxy, HAProxy ALOHA, Caddy, Traefik,
vsftpd, Serv-U, GLPI, IIS, Exchange, passerelle RDS, keystore Java, F5 BIG-IP,
Check Point, VMware Horizon UAG, et un connecteur générique par API.

**Vérification réelle** — une sonde rouvre une connexion TLS vers le service et compare
l'empreinte SHA-256 servie à celle attendue. Elle ne lit pas la base de données : elle
détecte donc le cas classique du certificat bien écrit sur le disque mais jamais rechargé
par le service.

**Renouvellement automatique** — déclenché à un pourcentage de la durée de vie restante,
puis redéploiement sur toutes les cibles actives.

---

## Ce qu'il ne fait pas

Il ne remplace pas **cert-manager**. Sur Kubernetes, gardez cert-manager : c'est le bon
outil, il est mature, et certfleet ne cherche pas à le concurrencer. certfleet couvre
le reste de votre parc.

---

## Architecture

Le hub n'ouvre **jamais** de connexion vers vos serveurs et ne détient **aucun**
identifiant sur eux. Un agent est installé sur chaque cible et interroge le hub.
Rien à ouvrir dans le pare-feu en entrée.

```
   ┌──────────┐   DNS-01    ┌─────────────┐
   │   ACME   │◄────────────│  fournisseur│
   │ (LE, …)  │             │     DNS     │
   └────┬─────┘             └─────────────┘
        │ certificat
        ▼
   ┌──────────────────────┐        sonde TLS
   │        hub           │───────────────────────┐
   │  émission · coffre   │                       │
   │  interface · API     │◄──── pull ────┐       │
   └──────────────────────┘               │       ▼
                                     ┌────┴────┐  vérifie l'empreinte
                                     │  agent  │  réellement servie
                                     │ (cible) │
                                     └─────────┘
```

La clé privée est chiffrée au repos (AES-256-GCM), la clé de chiffrement vit **hors base**,
et l'API ne l'expose jamais en lecture. Elle est transmise à l'agent par chiffrement
hybride : AES-256-CBC pour la clé, RSA-OAEP pour la clé AES, avec la clé publique que
l'agent a générée localement à son enrôlement. Le hub ne peut donc pas déchiffrer ce
qu'il envoie une fois posé.

Sur la cible, l'écriture passe par un helper `sudo` dédié qui valide les chemins et
n'autorise le rechargement que d'une **liste blanche** de commandes. Aucune exécution
arbitraire n'est possible, même si le hub était compromis.

---

## Démarrage

```bash
git clone https://github.com/stephkoh/certfleet.git
cd certfleet
cp .env.example .env

# Deux secrets à générer
echo "ADMIN_TOKEN=$(openssl rand -hex 32)"      >> .env
echo "CERT_VAULT_KEY=$(openssl rand -base64 32)" >> .env

docker compose up -d
```

Puis ouvrez `http://localhost:8080` et connectez-vous avec `ADMIN_TOKEN`.

### Sans Docker

```bash
npm install
export DATABASE_URL=postgres://user:pass@localhost:5432/certfleet
export ADMIN_TOKEN=…  CERT_VAULT_KEY=…
npm start
```

Node 20 ou plus, PostgreSQL 14 ou plus. Le schéma se crée au premier démarrage.

### Sur Kubernetes

```bash
docker build -t certfleet:local .          # ou utilisez l'image publiée
kubectl create namespace certfleet
kubectl -n certfleet create secret generic certfleet   --from-literal=DATABASE_URL="postgres://certfleet:MOTDEPASSE@certfleet-db:5432/certfleet"   --from-literal=POSTGRES_PASSWORD="MOTDEPASSE"   --from-literal=ADMIN_TOKEN="$(openssl rand -hex 32)"   --from-literal=CERT_VAULT_KEY="$(openssl rand -base64 32)"

kubectl apply -k deploy/k8s/base      # cluster
kubectl apply -k deploy/k8s/local     # poste de travail
```

Manifestes complets, pièges et points de vigilance : [`deploy/README.md`](deploy/README.md).

> **Un seul réplica, et c'est structurel.** Les tâches de renouvellement vivent
> dans le processus : deux répliques émettraient deux commandes ACME pour le
> même certificat. La stratégie de déploiement est `Recreate` pour cette raison.

### Installer un agent sur une cible

```bash
curl -fsSL https://votre-hub/api/agents/agent.sh -o certfleet-agent.sh
sudo bash certfleet-agent.sh enroll --hub https://votre-hub --token <jeton d'enrôlement>
```

L'agent génère sa paire de clés localement, s'enrôle, puis interroge le hub. Le helper
`sudo` et sa règle `sudoers` sont posés par le script d'installation.

---

---

## Comptes et Active Directory

Trois rôles, hiérarchiques :

| Rôle | Peut | Ne peut pas |
|---|---|---|
| `viewer` | consulter l'inventaire, l'échéancier, les sondes, les déploiements | aucune écriture |
| `operator` | tout ce qui précède, plus émettre, déployer, gérer cibles et sondes | télécharger une clé privée, gérer les comptes |
| `admin` | tout, y compris les clés privées, l'annuaire et les comptes | — |

Les comptes peuvent être **locaux** — mot de passe dérivé en scrypt avec un sel
par compte — ou venir de votre **Active Directory**. Dans ce second cas, le mot
de passe n'est jamais stocké ni relayé : il est vérifié par un simple bind sur
le contrôleur de domaine.

certfleet ne fait que **lire** l'annuaire. Un compte de service en lecture seule
suffit ; il n'a besoin d'aucune délégation d'écriture.

Tout se configure depuis **Comptes → Active Directory** : URL du contrôleur et
de son secours, base DN, compte de service, filtre, options TLS, et un bouton
*Tester* qui vous dit en une phrase si la connexion passe. Le mot de passe du
compte de service est chiffré en base avec la même clé que les clés privées, et
l'API ne le renvoie jamais.

Le rôle d'un compte d'annuaire se déduit de ses groupes :

```
CN=certfleet-admins  → admin
CN=equipe-infra      → operator
(sans correspondance) → rôle par défaut, viewer
```

Le rôle le plus fort l'emporte, et un rôle attribué à la main dans l'interface
n'est jamais écrasé tant qu'aucune correspondance de groupe ne s'applique.

### Premier démarrage

S'il n'existe aucun administrateur actif, certfleet en crée un et affiche son
mot de passe **une seule fois** dans les logs :

```
┌───────────────────────────────────────────────────────────
│ Aucun administrateur en base : compte initial créé.
│   identifiant  : admin
│   mot de passe : k3Jx8pQ2vLm
│ À changer à la première connexion — non réaffiché.
└───────────────────────────────────────────────────────────
```

`ADMIN_TOKEN` reste par ailleurs un accès de secours : il ouvre une session
administrateur sans passer par la base, ce qui dépanne quand l'annuaire est
tombé ou qu'un mot de passe est perdu. La page de connexion y donne accès par
le lien *Utiliser le jeton de secours*.

Chaque connexion, changement de rôle, émission et déploiement est consigné dans
le journal d'audit, consultable dans **Comptes → Journal d'audit**.

## Configuration

| Variable | Rôle |
|---|---|
| `DATABASE_URL` | chaîne de connexion PostgreSQL |
| `ADMIN_TOKEN` | jeton d'accès à l'interface et à l'API |
| `CERT_VAULT_KEY` | 32 octets base64, chiffre les clés privées. **Hors base, obligatoire.** |
| `COOKIE_SECURE` | `false` uniquement en développement local sans HTTPS |
| `MONITOR_INTERVAL_MIN` | cadence de la sonde TLS (défaut 360) |
| `RENEW_INTERVAL_MIN` | cadence du contrôle de renouvellement (défaut 720) |
| `BOOTSTRAP_ADMIN` / `BOOTSTRAP_PASSWORD` | premier compte administrateur ; sans mot de passe, il est tiré au hasard et affiché une fois |
| `SESSION_HOURS` | durée de validité d'une session (défaut 12) |
| `TRUST_PROXY` | `true` derrière un reverse proxy, pour journaliser l'adresse réelle du client |
| `LDAP_*` | valeurs par défaut de l'annuaire ; préférez l'interface, qui chiffre le mot de passe |

Sans `CERT_VAULT_KEY`, une clé est générée et **stockée en base** — ce qui revient à
laisser la clé sur la serrure. Le démarrage vous en avertit.

---

---

## Tests

```bash
npm test            # syntaxe + tests unitaires, sans base de données
npm run test:api    # test d'intégration : monte une base jetable dans Docker
```

`test/api.sh` démarre une PostgreSQL éphémère, lance le serveur et exerce
l'API de bout en bout — authentification, cloisonnement des rôles, chiffrement
des secrets en base, enrôlement d'agent, journal d'audit — puis nettoie tout.

## État du projet

Version **0.1.0**, extraite d'un ERP interne où elle tourne en production depuis 2026 :
émission ACME, déploiement sur Serv-U et HAProxy ALOHA, sonde de vérification et
renouvellement automatique y sont éprouvés. La gestion des comptes et
l'authentification par annuaire ont été ajoutées lors de l'extraction et sont
couvertes par les tests d'intégration, mais n'ont pas encore l'usure du terrain.

Les connecteurs marqués « à valider » dans l'onglet *Types de cible* n'ont pas encore
été confrontés au terrain. Les retours sont les bienvenus.

---

## Licence

**AGPL-3.0-or-later.** Libre d'usage, de modification et de redistribution.

Si vous exploitez certfleet comme service réseau, l'AGPL vous impose de publier vos
modifications. Si cela ne convient pas à votre organisation, une **licence commerciale**
lève cette obligation : voir [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).

Le projet est développé sur du temps personnel. Si certfleet vous fait gagner du temps,
le bouton **Sponsor** en haut de cette page finance sa maintenance — notamment le suivi
des évolutions ACME et l'ajout de connecteurs.
