FROM docker.io/clojure:temurin-17-tools-deps

# Modified by Barayamal on 26 July 2026 so the production runtime basis is
# fully resolved at image build time and can run on a private, no-egress
# network without entering the worker's restart loop.

WORKDIR /app
COPY . .

# Resolve the exact runtime alias first. The former `-A:dev -P` command did not
# populate every artifact used by `clojure -M:run` and caused repeated Maven
# lookups and high CPU when the container had no internet egress.
RUN clojure -P -M:run && clojure -P -M:dev

CMD ["./bin/run"]
