FROM node:20-slim

RUN apt-get update && apt-get install -y \
  aapt \
  openjdk-17-jre-headless \
  unzip \
  zip \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json .
RUN npm install --production

COPY . .
RUN mkdir -p uploads workspace

EXPOSE 3000
CMD ["npm", "start"]
