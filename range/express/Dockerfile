# brot-glm2 step 3 — express surface. OUR app; exact base pins, no platform pin.
ARG NODE_IMAGE=node:24.22.0
FROM ${NODE_IMAGE}
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY app.js ./
CMD ["node", "app.js"]
