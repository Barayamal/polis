FROM docker.io/library/clojure:temurin-17-tools-deps@sha256:8250a7e6b20954680c2e3bf2e84ad4caab1c5ea68c56c28bca41fb9ac5a2e96e

# Modified by Barayamal on 26 July 2026 so the production runtime basis is
# fully resolved at image build time and can run on a private, no-egress
# network without entering the worker's restart loop.

WORKDIR /app
COPY . .

# Resolve only the exact runtime alias. The former `-A:dev -P` command did not
# populate every artifact used by `clojure -M:run` and also retained
# development-only nREPL/report tooling in the production worker image.
RUN clojure -P -M:run

CMD ["./bin/run"]
