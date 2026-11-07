FROM node:24-alpine@sha256:a34ab6d7f6f4813f4d0c5469d74685604b962fbdbf5793a7bc7b4998ecb867c8
WORKDIR /opt/vortex
# No dependency install, host folders, Docker socket or credentials in the image.
COPY --chown=node:node package.json server.mjs ./
COPY --chown=node:node src/ ./src/
COPY --chown=node:node public/ ./public/
COPY --chown=node:node ai/ ./ai/
COPY --chown=node:node lab/ ./lab/
USER node
ENV NODE_ENV=production VORTEX_CONTAINER=1
CMD ["node", "server.mjs"]
