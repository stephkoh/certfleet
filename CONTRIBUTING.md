# Contribuer à certfleet

Les contributions sont bienvenues : corrections, connecteurs pour de nouveaux
équipements, retours de terrain sur les types marqués « à valider ».

Avant la première, il y a un point à régler. Il est expliqué franchement plus
bas, parce qu'une cession de droits qu'on ne comprend pas ne vaut rien.

---

## Accord de contribution

certfleet est publié sous **AGPL-3.0-or-later**, et une **licence commerciale**
est proposée aux organisations que le copyleft de l'AGPL ne peut pas accueillir
(voir [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md)). C'est ce qui finance la
maintenance du projet.

Ce double régime n'est possible que si une seule partie peut concéder le code
sous les deux licences. Sans accord, chaque contributeur conserve ses droits sur
son apport : le projet ne pourrait plus proposer de licence commerciale couvrant
l'ensemble du code, et cela ne serait pas rattrapable après coup.

D'où l'accord ci-dessous. Il ne vous retire rien : vous restez auteur et
titulaire des droits sur votre contribution, et vous pouvez continuer à en faire
ce que vous voulez, y compris la reverser à d'autres projets.

### Ce que vous accordez

En proposant une contribution, vous déclarez et acceptez ce qui suit.

**1. Vous en avez le droit.** La contribution est votre travail original, ou
vous disposez des droits nécessaires pour la soumettre. Si vous l'écrivez dans
le cadre de votre emploi, vous vous êtes assuré que votre employeur ne s'y
oppose pas.

**2. Vous conservez vos droits.** Vous restez titulaire du droit d'auteur sur
votre contribution. Rien ici n'est une cession.

**3. Vous accordez une licence large.** Vous accordez au mainteneur du projet
une licence perpétuelle, mondiale, non exclusive, irrévocable et gratuite, avec
droit de sous-licencier, pour reproduire, modifier, distribuer et exploiter
votre contribution, **y compris sous des conditions autres que l'AGPL** — ce qui
inclut la licence commerciale du projet.

**4. Brevets.** Si votre contribution est couverte par un brevet dont vous
disposez, vous accordez la même licence sur les revendications nécessaires à son
utilisation dans certfleet.

**5. Fournie en l'état.** Vous n'apportez aucune garantie sur votre
contribution, sauf mention écrite contraire.

### Comment l'accepter

Signez chacun de vos commits :

```bash
git commit -s -m "Votre message"
```

L'option `-s` ajoute une ligne `Signed-off-by:` avec votre nom et votre adresse.
Cette signature vaut acceptation des cinq points ci-dessus.

Si vous préférez que ce soit explicite, ajoutez dans la description de la pull
request :

> J'accepte les termes de l'accord de contribution du fichier CONTRIBUTING.md.

> **Ce texte n'est pas un avis juridique.** Il reprend la structure des accords
> utilisés par les projets en double licence, mais si vous contribuez au nom
> d'une entreprise, ou si vous comptez vous appuyer dessus pour une transaction
> commerciale, faites-le relire par un juriste.

---

## Avant d'ouvrir une pull request

Ces trois commandes doivent passer. Aucune version ne part sans elles.

```bash
npm test           # syntaxe, tests unitaires, audit de cohérence
npm run test:api   # intégration sur une base PostgreSQL jetable (exige Docker)
```

L'audit (`npm run audit`) vérifie aussi qu'aucun secret, nom d'hôte interne ou
adresse réelle ne s'est glissé dans le code. Il s'exécute avec `npm test`.

## Ce qui aide vraiment

**Les connecteurs manquants.** F5 BIG-IP, Check Point et VMware Horizon UAG sont
déclarés mais non implémentés — seul ALOHA l'est. Chacun demande de parler à
l'API d'administration de l'appliance. Si vous en administrez une, vous êtes
mieux placé que quiconque pour l'écrire.

**Les retours de terrain.** Les types marqués « à valider » n'ont jamais été
confrontés à un vrai serveur. Nous dire qu'un connecteur fonctionne — ou ce
qu'il a fallu changer — vaut autant qu'un correctif.

**Les fournisseurs DNS.** Seul Gandi est fourni. La structure est enfichable :
`src/lib/dns/gandi.js` sert de modèle, une centaine de lignes suffisent.

## Écrire du code qui ressemble au reste

- Les commentaires expliquent **pourquoi**, pas ce que le code fait déjà lire.
  Ceux qui décrivent un piège rencontré valent de l'or : gardez-les.
- Aucune dépendance nouvelle sans raison forte. Un outil d'infrastructure doit
  encore fonctionner dans cinq ans.
- Ce qui touche à la sécurité — chiffrement, authentification, exécution sur une
  cible — mérite un test dans `test/smoke.mjs` ou `test/api.sh`.
- Les messages d'erreur s'adressent à quelqu'un qui débogue à trois heures du
  matin : dites ce qui a échoué et ce qu'il faut faire.

## Signaler un problème de sécurité

N'ouvrez pas d'issue publique : la marche à suivre est dans
[SECURITY.md](SECURITY.md).
