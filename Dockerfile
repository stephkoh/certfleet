FROM node:20-alpine

# openssl : utilisé par l'agent et pour les contrôles de chaîne.
RUN apk add --no-cache openssl

WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev

COPY src ./src
COPY public ./public
COPY agent ./agent
COPY test ./test

ENV NODE_ENV=production
EXPOSE 8080

# Pas de root : le conteneur n'a aucune raison d'en avoir besoin.
USER node

CMD ["node", "src/server.js"]
