# Déploiement

Trois façons de faire tourner certfleet, de la plus simple à la plus durable.

| | Pour quoi | Où |
|---|---|---|
| **Docker Compose** | évaluer, développer, petite installation | [`docker-compose.yml`](../docker-compose.yml) |
| **Kubernetes — poste de travail** | essayer sur Docker Desktop, kind, minikube | [`k8s/local/`](k8s/local/) |
| **Kubernetes — cluster** | production | [`k8s/base/`](k8s/base/) |

---

## Docker Compose

```bash
cp .env.example .env
echo "POSTGRES_PASSWORD=$(openssl rand -hex 16)" >> .env
echo "ADMIN_TOKEN=$(openssl rand -hex 32)"       >> .env
echo "CERT_VAULT_KEY=$(openssl rand -base64 32)" >> .env

docker compose up -d
docker compose logs app        # le mot de passe initial y est affiché une fois
```

Puis `http://localhost:8080`.

La base n'est pas exposée à l'hôte, l'application tourne en utilisateur non
privilégié, et le volume `db` survit à un `docker compose down`. Pour tout
effacer, y compris les certificats : `docker compose down -v`.

---

## Kubernetes — poste de travail

```bash
docker build -t certfleet:local .

kubectl create namespace certfleet
kubectl -n certfleet create secret generic certfleet \
  --from-literal=DATABASE_URL="postgres://certfleet:local@certfleet-db:5432/certfleet" \
  --from-literal=POSTGRES_PASSWORD="local" \
  --from-literal=ADMIN_TOKEN="$(openssl rand -hex 32)" \
  --from-literal=CERT_VAULT_KEY="$(openssl rand -base64 32)" \
  --from-literal=BOOTSTRAP_PASSWORD="MotDePasseLocal1234"

kubectl apply -k deploy/k8s/local
kubectl -n certfleet port-forward svc/certfleet 8080:80
```

Puis `http://localhost:8080`.

**Deux pièges propres à Docker Desktop**, tous deux constatés à l'usage :

Son Kubernetes est désormais provisionné par **kind**. Le nœud ne publie sur la
machine que le port de l'API (6443), donc le **NodePort 30080 reste
injoignable** depuis l'hôte — et sans message d'erreur, la connexion échoue
simplement. `port-forward` fonctionne partout, c'est la voie à privilégier.

kind n'utilise pas non plus le magasin d'images de Docker. Si le pod reste en
`ErrImageNeverPull`, importez l'image dans le nœud :

```bash
kind load docker-image certfleet:local --name desktop
# ou, sans le binaire kind :
docker save certfleet:local | \
  docker exec -i desktop-control-plane ctr -n k8s.io images import -
```

---

## Kubernetes — cluster

```bash
kubectl create namespace certfleet
kubectl -n certfleet create secret generic certfleet \
  --from-literal=DATABASE_URL="postgres://certfleet:MOTDEPASSE@certfleet-db:5432/certfleet" \
  --from-literal=POSTGRES_PASSWORD="MOTDEPASSE" \
  --from-literal=ADMIN_TOKEN="$(openssl rand -hex 32)" \
  --from-literal=CERT_VAULT_KEY="$(openssl rand -base64 32)"

# Adaptez le nom d'hôte et l'émetteur TLS dans k8s/base/06-ingress.yaml
kubectl apply -k deploy/k8s/base
```

Le Secret est créé en ligne de commande, jamais dans un fichier versionné.
`k8s/base/01-secret.example.yaml` n'est là qu'à titre de référence et n'est pas
inclus dans la `kustomization`.

### Points de vigilance

**Un seul réplica, et c'est structurel.** certfleet porte deux tâches de fond
dans le processus : la sonde TLS et le renouvellement ACME. Deux répliques
feraient tourner deux renouvellements en parallèle — commandes ACME en double,
quotas Let's Encrypt consommés pour rien, et deux déploiements concurrents sur
la même cible. La stratégie est `Recreate` pour que deux pods ne coexistent pas
même le temps d'une mise à jour. Passer à l'échelle demanderait d'abord un
verrou partagé.

**`CERT_VAULT_KEY` chiffre les clés privées de tous vos certificats.** La perdre
rend le coffre illisible. Sauvegardez-la hors du cluster, au même titre qu'une
clé de chiffrement de sauvegarde.

**La base contient ces clés privées, chiffrées.** Sauvegardez-la comme telle. Si
vous disposez déjà d'un PostgreSQL — managé, opérateur CloudNativePG, instance
existante — retirez `03-postgres.yaml` de la `kustomization` et renseignez
simplement `DATABASE_URL`.

**Les agents doivent joindre l'URL de l'Ingress** depuis vos réseaux : c'est par
là qu'ils viennent chercher leurs commandes. Le hub, lui, n'ouvre jamais de
connexion vers vos serveurs.

**Le certificat du hub lui-même** est confié à cert-manager dans l'Ingress.
C'est bien son rôle dans Kubernetes, et certfleet ne cherche pas à l'y
remplacer.

---

## Configuration

Toutes les variables sont documentées dans [`.env.example`](../.env.example) et
dans le [README](../README.md#configuration). En Kubernetes, elles se
répartissent entre le `ConfigMap` (non sensible) et le `Secret`.

L'annuaire Active Directory se configure de préférence depuis l'interface
— **Comptes → Active Directory** — plutôt que par variables d'environnement :
le mot de passe du compte de service y est alors chiffré en base avec la même
clé que les clés privées.
