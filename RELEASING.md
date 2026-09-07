# Publier une version

Mémo pour livrer un correctif ou une nouveauté, sans se demander à chaque fois
dans quel ordre faire les choses.

## Choisir le numéro

| Le changement… | Version | Exemple |
|---|---|---|
| corrige seulement, rien à faire côté utilisateur | **correctif** — `0.1.0 → 0.1.1` | un connecteur qui échouait |
| ajoute sans rien casser | **mineur** — `0.1.1 → 0.2.0` | un nouveau type de cible |
| impose une action à une installation existante | **majeur** — `0.2.0 → 1.0.0` | un changement de schéma non automatique |

Tant que la version majeure est `0`, une version mineure peut casser
l'interface : c'est admis, mais il faut le dire en tête de section du journal.

## Étapes

```bash
# 1. Vérifier — aucune version ne part sans ces trois-là
npm test              # syntaxe, tests unitaires, audit de cohérence
npm run test:api      # intégration sur une base PostgreSQL jetable

# 2. Numéroter
npm version 0.1.1 --no-git-tag-version     # met à jour package.json

# 3. Journaliser
#    Déplacer les entrées de « Non publié » vers une nouvelle section
#    dans CHANGELOG.md, avec la date du jour.

# 4. Committer et étiqueter
git add -A
git commit -m "Version 0.1.1 — <ce que ça corrige>"
git tag -a v0.1.1 -m "certfleet 0.1.1"
git push && git push --tags
```

L'étiquette compte : c'est elle qui permet à quelqu'un de revenir à une version
précise, et c'est elle que GitHub reprend pour créer la page de publication.

## Publier sur GitHub

Une fois l'étiquette poussée, `https://github.com/stephkoh/certfleet/releases/new`
propose la version dans la liste. Collez-y la section correspondante du journal.

## Revenir en arrière

```bash
git checkout v0.1.0        # revenir à une version publiée
git revert <commit>        # annuler un changement précis, en gardant l'historique
```

Ne réécrivez pas l'historique déjà poussé : d'autres peuvent l'avoir récupéré.
Un `revert` est toujours préférable à un `push --force`.

## Ce qui ne doit jamais partir dans une version

- Un fichier `.env`, un jeton, une clé privée — le fichier `.gitignore` les
  exclut, mais `npm run audit` le vérifie aussi.
- Une base de données ou un export de données réelles.
- Un nom d'hôte, une adresse IP ou un nom de client internes : l'audit signale
  les références connues, mais il ne peut pas tout deviner.
