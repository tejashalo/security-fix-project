# VibeGuard — tiny image, no npm dependencies to install.
FROM node:22-alpine
RUN apk add --no-cache git
WORKDIR /app
COPY package.json ./
COPY server ./server
COPY public ./public
COPY bin ./bin
ENV NODE_ENV=production PORT=3000
USER node
EXPOSE 3000
HEALTHCHECK CMD wget -qO- http://127.0.0.1:3000/api/health || exit 1
CMD ["node", "server/index.js"]
