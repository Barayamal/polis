FROM docker.io/library/node:24-alpine@sha256:a0b9bf06e4e6193cf7a0f58816cc935ff8c2a908f81e6f1a95432d679c54fbfd AS fncp-busybox-fixed

RUN apk add --no-cache \
  build-base=0.5-r4 \
  curl=8.21.0-r0 \
  file=5.47-r2 \
  linux-headers=7.0.0-r1 \
  patch=2.8-r0 \
  pkgconf=2.5.1-r0 \
  utmps-dev=0.1.3.3-r0 \
  utmps-static=0.1.3.3-r0
COPY busybox-fixed /opt/fncp-busybox-fix
RUN chmod 0555 /opt/fncp-busybox-fix/build-fixed-busybox.sh \
  && /opt/fncp-busybox-fix/build-fixed-busybox.sh

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

# Build a deliberately bounded Java 17 runtime. The selected modules cover the
# worker's Clojure compiler, JDBC, XML, crypto and management paths.
# java.desktop is retained because the matrix/data runtime links
# java.beans.PropertyChangeEvent while booting; the worker does not invoke GUI
# or audio paths. JDK build tools and package managers remain excluded.
FROM docker.io/library/amazoncorretto:17-alpine@sha256:e1138bf0cca62e04692de650ffe8923f35c39fcb554458c7acd98efc2d135144 AS fncp-jre-build

RUN apk add --no-cache binutils=2.45.1-r1

RUN "$JAVA_HOME/bin/jlink" \
      --add-modules \
java.base,java.compiler,java.desktop,java.instrument,java.logging,java.management,java.naming,java.net.http,java.security.jgss,java.security.sasl,java.sql,java.transaction.xa,java.xml,jdk.crypto.ec,jdk.management,jdk.unsupported,jdk.zipfs \
      --compress=2 \
      --no-header-files \
      --no-man-pages \
      --strip-debug \
      --output /opt/fncp-jre \
    && test "$(/opt/fncp-jre/bin/java --list-modules | wc -l)" -lt 40 \
    && test ! -e /opt/fncp-jre/bin/javac \
    && test ! -e /opt/fncp-jre/bin/jlink

FROM docker.io/library/alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS runtime

ARG SOURCE_REVISION
RUN case "$SOURCE_REVISION" in \
      ""|*[!0-9a-f]*) exit 1 ;; \
    esac \
    && test "${#SOURCE_REVISION}" -eq 40

ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"

WORKDIR /app

RUN apk add --no-cache \
      ca-certificates-bundle=20260611-r0 \
      zlib=1.3.2-r0

LABEL org.barayamal.fncp.busybox.remediation="CVE-2025-60876-upstream-patch" \
      org.opencontainers.image.source="https://github.com/Barayamal/polis" \
      org.opencontainers.image.revision="${SOURCE_REVISION}"
COPY --from=fncp-busybox-fixed /out/busybox /bin/busybox
RUN set -eu; \
  test "$(readlink -f /bin/sh)" = /bin/busybox; \
  test "$(readlink -f /usr/bin/wget)" = /bin/busybox; \
  for applet in cat timeout; do /bin/busybox --list | grep -Fxq "$applet"; done; \
  bad_url="$(printf 'http://127.0.0.1/%b' '\rX-FNCP: injected')"; \
  if /usr/bin/wget "$bad_url" >/tmp/wget.stdout 2>/tmp/wget.stderr; then exit 1; fi; \
  grep -Fq 'Unencoded control character found in the URL!' /tmp/wget.stderr; \
  rm -f /tmp/wget.stdout /tmp/wget.stderr

COPY --from=fncp-jre-build /opt/fncp-jre ${JAVA_HOME}
COPY --from=build --chown=65532:65532 /runtime/app ./

RUN classpath=$(cat /app/classpath) \
    && origin=$(${JAVA_HOME}/bin/java \
      -cp "$classpath" \
      clojure.main \
      -e '(print (-> (Class/forName "clojure.core.matrix.random.RandomSeq") .getProtectionDomain .getCodeSource .getLocation str))') \
    && test "$origin" = 'file:/app/lib/core.matrix-0.63.0.jar' \
    && if ! ${JAVA_HOME}/bin/java \
      -cp "$classpath" \
      clojure.main \
      -e '(require (quote polismath.runner) (quote polismath.components.core-matrix-boot) (quote com.stuartsierra.component)) (let [probe (polismath.components.core-matrix-boot/create-core-matrix-booter {:config {:math {:matrix-implementation :vectorz}}})] (com.stuartsierra.component/start probe)) (println "FNCP math runtime boot probe passed")' \
      >/tmp/fncp-math-boot.log 2>&1; then \
        cat /tmp/fncp-math-boot.log >&2; \
        exit 1; \
      fi \
    && if grep -Eq 'ClassNotFoundException|NoClassDefFoundError|Math worker exited.*restarting' \
      /tmp/fncp-math-boot.log; then \
        cat /tmp/fncp-math-boot.log >&2; \
        exit 1; \
      fi \
    && grep -Fxq 'FNCP math runtime boot probe passed' /tmp/fncp-math-boot.log \
    && rm -f /tmp/fncp-math-boot.log \
    && test "$(${JAVA_HOME}/bin/java --list-modules | wc -l)" -lt 40 \
    && test ! -e ${JAVA_HOME}/bin/javac

USER 65532:65532

ENTRYPOINT []
CMD ["./bin/run"]
