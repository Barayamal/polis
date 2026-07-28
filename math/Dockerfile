FROM docker.io/library/clojure:temurin-17-tools-deps@sha256:8250a7e6b20954680c2e3bf2e84ad4caab1c5ea68c56c28bca41fb9ac5a2e96e AS build

# Modified by Barayamal on 26 July 2026 so the production runtime basis is
# fully resolved at image build time and can run on a private, no-egress
# network without entering the worker's restart loop.

WORKDIR /app
COPY . .

# Resolve only the exact runtime alias. The former `-A:dev -P` command did not
# populate every artifact used by `clojure -M:run` and also retained
# development-only nREPL/report tooling in the production worker image.
RUN clojure -P -M:run \
    && mkdir -p /runtime/app/lib \
    && printf '%s' '/app/src:/app/resources' > /runtime/app/classpath \
    && clojure -Spath -M:run \
      | tr ':' '\n' \
      | while IFS= read -r artifact; do \
          case "$artifact" in \
            *.jar) \
              target="/runtime/app/lib/$(basename "$artifact")"; \
              if [ -e "$target" ]; then \
                if ! cmp -s "$artifact" "$target"; then \
                  echo "Runtime JAR basename collision: $artifact and $target" >&2; \
                  exit 1; \
                fi; \
              else \
                cp "$artifact" "$target"; \
              fi; \
              printf ':/app/lib/%s' "$(basename "$artifact")" \
                >> /runtime/app/classpath \
              ;; \
          esac; \
        done \
    && cp -R src resources bin /runtime/app/ \
    && cp system.properties /runtime/app/

FROM docker.io/library/clojure:temurin-17-tools-deps@sha256:8250a7e6b20954680c2e3bf2e84ad4caab1c5ea68c56c28bca41fb9ac5a2e96e AS runtime

RUN rm -rf /usr/local/lib/clojure \
    /usr/local/bin/clj \
    /usr/local/bin/clojure

WORKDIR /app
COPY --from=build --chown=65532:65532 /runtime/app ./

RUN classpath=$(cat /app/classpath) \
    && origin=$(/opt/java/openjdk/bin/java \
      -cp "$classpath" \
      clojure.main \
      -e '(print (-> (Class/forName "clojure.core.matrix.random.RandomSeq") .getProtectionDomain .getCodeSource .getLocation str))') \
    && test "$origin" = 'file:/app/lib/core.matrix-0.63.0.jar'

USER 65532:65532

CMD ["./bin/run"]
