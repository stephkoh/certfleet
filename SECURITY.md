# Politique de sécurité

certfleet détient des clés privées de certificats et s'exécute avec des droits
élevés sur les serveurs qu'il administre. Une faille y a des conséquences
directes. Les signalements sont pris au sérieux.

## Signaler une vulnérabilité

**N'ouvrez pas d'issue publique.** Passez par le signalement privé de GitHub :

> onglet **Security** du dépôt → **Report a vulnerability**

Le rapport reste visible de vous seul et du mainteneur jusqu'à publication d'un
correctif.

Ce qui aide à traiter vite :

- la version concernée (`git describe --tags`, ou le numéro de la release) ;
- ce qu'un attaquant peut obtenir, et depuis quelle position — accès réseau,
  compte `viewer`, agent compromis ;
- de quoi reproduire : la séquence minimale suffit, un exploit complet n'est pas
  nécessaire.

Comptez quelques jours pour un premier retour. Ce projet est maintenu sur du
temps personnel : ce n'est pas un engagement contractuel, et les délais sont
annoncés honnêtement plutôt que promis puis tenus à moitié.

## Versions suivies

Seule la dernière version publiée reçoit des correctifs de sécurité. Tant que la
version majeure est `0`, il n'y a pas de branche de maintenance : un correctif
donne lieu à une nouvelle version corrective.

## Ce qui compte comme vulnérabilité

Sont traités comme tels, entre autres :

- l'accès à une clé privée de certificat sans le rôle requis ;
- l'exécution de code sur une cible par un chemin autre que le déploiement
  prévu, ou le contournement de la liste blanche du helper `sudo` ;
- l'élévation d'un rôle `viewer` ou `operator` vers `admin` ;
- la lecture des secrets d'une cible — mot de passe d'API, d'un keystore — par
  un compte qui ne devrait pas y accéder ;
- l'usurpation d'un agent permettant de recevoir un certificat destiné à un
  autre serveur.

## Ce qui n'en est pas

Ces points sont documentés et assumés :

- **Le jeton `ADMIN_TOKEN` donne un accès administrateur complet.** C'est sa
  raison d'être : dépanner quand l'annuaire est tombé ou qu'un mot de passe est
  perdu. Protégez-le comme un mot de passe root.
- **L'agent s'exécute en root sur sa cible.** Il ne peut pas en être autrement
  pour écrire dans `/etc` et recharger un service. Le helper restreint ce qu'il
  peut lancer à une liste blanche.
- **Un agent compromis peut lire les certificats qui lui sont destinés.** Le
  chiffrement de bout en bout protège le transport, pas une machine déjà aux
  mains d'un attaquant.
- **`CERT_VAULT_KEY` absente fait générer une clé stockée en base**, ce qui
  revient à laisser la clé sur la serrure. Le démarrage l'annonce, et la
  documentation insiste : cette variable doit être définie.

## Ce que fait certfleet pour limiter les dégâts

- Le hub n'ouvre jamais de connexion vers vos serveurs et ne détient aucun
  identifiant sur eux : les agents l'interrogent.
- Les clés privées sont chiffrées au repos en AES-256-GCM, avec une clé qui vit
  hors de la base.
- La clé privée transmise à un agent est chiffrée avec la clé publique que cet
  agent a générée localement : le hub ne peut pas relire ce qu'il envoie.
- Les paramètres sensibles d'une cible voyagent dans un canal chiffré distinct,
  jamais en clair dans la file de commandes.
- Le helper `sudo` valide les chemins et n'autorise le rechargement que d'une
  liste blanche de commandes.
- Les jetons de session ne sont stockés que hachés, et toute action d'écriture
  est journalisée.
