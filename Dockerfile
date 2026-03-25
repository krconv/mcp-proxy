FROM node:22-bookworm-slim AS builder

WORKDIR /build
COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile
COPY tsconfig.json ./
COPY src/ src/
RUN yarn build && rm -rf node_modules && yarn install --frozen-lockfile --production

FROM node:22-bookworm-slim
WORKDIR /app
COPY --from=builder /build/dist dist/
COPY --from=builder /build/node_modules node_modules/
COPY --from=builder /build/package.json .

ENV PORT=9000
ENV DATA_DIR=/data
EXPOSE 9000

CMD ["node", "dist/index.js"]
