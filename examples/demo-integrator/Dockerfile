FROM node:24-bookworm-slim
WORKDIR /app
COPY packages/widget/src ./packages/widget/src
COPY examples/demo-integrator/integrator.js examples/demo-integrator/upstream.js examples/demo-integrator/package.json ./examples/demo-integrator/
COPY examples/demo-integrator/site ./examples/demo-integrator/site
USER node
WORKDIR /app/examples/demo-integrator
CMD ["node","integrator.js"]
