# In-browser terminal backend image.
# Build context = REPO ROOT:  docker build -f terminal-server/Dockerfile .
# Ships bash + kubectl + the prebuilt checker + the lab manifests, so the shell
# in the browser is fully equipped to run the CTF against the in-cluster API.
#
# Uses the small node:20-bookworm-slim base (already cached from the web build)
# and a PREBUILT node-pty, so there is no native compile and no large/flaky
# base-image pull. kubectl and the checker are copied in from the build context
# (downloaded/built on the host by deploy/build.sh).
FROM node:20-bookworm-slim

WORKDIR /app
COPY terminal-server/package.json ./
RUN npm install --omit=dev
COPY terminal-server/server.js ./

# kubectl (linux, matching arch) is placed in the context by deploy/build.sh
COPY terminal-server/bin/kubectl /usr/local/bin/kubectl
COPY terminal-server/bin/owasp-k8s-checker /usr/local/bin/owasp-k8s-checker
RUN chmod +x /usr/local/bin/kubectl /usr/local/bin/owasp-k8s-checker

# The shell drops into a workspace with the labs + docs.
WORKDIR /workspace
COPY labs ./labs
COPY README.md ./

ENV TERMINAL_CWD=/workspace \
    PORT=7681 \
    TERMINAL_SHELL=bash
EXPOSE 7681
CMD ["node", "/app/server.js"]
