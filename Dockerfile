# Prac360 server in a container (for Railway, Fly.io, a VPS …). Keep /data on a volume.
FROM node:20-alpine
WORKDIR /app
COPY . .
ENV DATA_DIR=/data PORT=8360
EXPOSE 8360
CMD ["node", "server.js"]
