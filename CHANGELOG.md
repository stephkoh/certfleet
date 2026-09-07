# Journal des versions

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).
Ce projet suit le [versionnage sémantique](https://semver.org/lang/fr/) :

- **majeur** — une installation existante doit intervenir pour migrer ;
- **mineur** — nouveauté rétrocompatible ;
- **correctif** — correction seule, aucune action requise.

Tant que la version majeure est `0`, l'interface peut changer d'une version
mineure à l'autre. Les changements qui cassent quelque chose sont signalés en
tête de section.

## [Non publié]

### Ajouté

- `CONTRIBUTING.md` : accord de contribution permettant au projet de rester
  publié à la fois sous AGPL-3.0 et sous licence commerciale, et guide pratique
  pour proposer un correctif ou un connecteur.
- Gabarit de pull request rappelant les vérifications attendues et l'accord.
- `SECURITY.md` : comment signaler une vulnérabilité, ce qui en est une, et ce
  qui relève au contraire d'un choix de conception assumé.

### Corrigé

- **Le fichier `LICENSE` contenait la GPL-3.0 et non l'AGPL-3.0**, alors que
  toute la documentation annonçait l'AGPL. La GPL n'a pas de clause de réseau :
  une version modifiée pouvait être exploitée en service réseau sans que ses
  modifications soient publiées. Le texte officiel de l'AGPL-3.0 le remplace.

## [0.1.0] — 2026-09-07

Première version publique, extraite d'un module existant et remise à plat pour
un usage générique.

### Ajouté

- Client **ACME RFC 8555** sans dépendance externe : challenge DNS-01, compte
  ES256, CSR généré en interne, fournisseur DNS enfichable (Gandi fourni).
- Déploiement sur **18 types de cible** : nginx, Apache, HAProxy, HAProxy ALOHA,
  Caddy, Traefik, vsftpd, Serv-U, GLPI, IIS, Exchange, passerelle RDS, keystore
  Java, F5 BIG-IP, Check Point, VMware Horizon UAG, connecteur générique, et
  Kubernetes en supervision seule.
- **Sonde TLS de vérification** : l'empreinte réellement servie est comparée à
  celle attendue, ce qui détecte le certificat écrit sur disque mais jamais
  rechargé par le service.
- Renouvellement et redéploiement automatiques.
- **Agent Linux** et **agent Windows** (PowerShell 7), installateurs clés en
  main servis par le hub, minuterie systemd ou tâche planifiée.
- **Comptes et rôles** : viewer / operator / admin, comptes locaux en scrypt ou
  comptes Active Directory vérifiés par bind, rôle déduit des groupes.
- Journal d'audit, sessions révocables, jeton de secours.
- Déploiement **Docker Compose** et **Kubernetes** (kustomize, base et poste de
  travail).

### Sécurité

- Le hub n'ouvre jamais de connexion vers les cibles et ne détient aucun
  identifiant sur elles : les agents interrogent le hub.
- Clés privées chiffrées en AES-256-GCM, clé de coffre hors base.
- Transmission à l'agent par chiffrement hybride RSA-OAEP + AES-256-CBC : le
  hub ne peut pas relire ce qu'il a envoyé.
- Les paramètres sensibles d'une cible voyagent dans un canal chiffré distinct,
  jamais en clair dans la file de commandes.
- Écriture sur la cible via un helper `sudo` à liste blanche de commandes.

### Limites connues

- Les connecteurs **F5, Check Point, UAG et générique** sont déclarés mais **non
  implémentés** : seul ALOHA l'est. Le déploiement est refusé avec un message
  explicite plutôt que de partir dans le vide.
- L'agent Windows exige **PowerShell 7** : en 5.1, l'import d'une clé PKCS#8
  n'existe pas.
- Un seul réplica, et c'est structurel : les tâches de renouvellement vivent
  dans le processus.
- Le marquage « testé » des types de cible est **propre à chaque installation** :
  une instance neuve repart avec tous les types à valider.

[Non publié]: https://github.com/stephkoh/certfleet/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/stephkoh/certfleet/releases/tag/v0.1.0
