FROM node:22-alpine

RUN apk add --no-cache fping iputils traceroute

WORKDIR /app

COPY package.json ./
RUN npm install --no-audit --no-fund

COPY src ./src
COPY public ./public
COPY test ./test
COPY .env.example ./

EXPOSE 3000

CMD ["npm", "start"]
