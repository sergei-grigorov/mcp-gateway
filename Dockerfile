# Шлюз коннекторов: OAuth, вход владельца, маршрутизация. Зависимостей нет.
FROM node:24-alpine
WORKDIR /app
COPY package.json ./
COPY server ./server
ENV NODE_ENV=production HOST=0.0.0.0 PORT=48678 DATA_DIR=/data
USER node
EXPOSE 48678
CMD ["node", "server/index.js"]
