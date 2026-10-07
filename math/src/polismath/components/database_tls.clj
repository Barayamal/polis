(ns polismath.components.database-tls
  "Explicit JDBC server authentication for the dedicated release profile."
  (:require [clojure.string :as string])
  (:import (java.net URI URLDecoder)
           (java.nio.charset StandardCharsets)
           (java.nio.file Files Paths LinkOption)
           (java.io ByteArrayInputStream)
           (java.security.cert CertificateFactory X509Certificate)))

(defn- invalid! []
  ;; A URI or parser cause can contain credentials. Expose only a fixed category.
  (throw (ex-info "MATH_DATABASE_TLS_CONFIGURATION_INVALID" {})))

(defn- clean-string? [value]
  (and (string? value) (not (string/blank? value))
       (not (re-find #"[\p{Cntrl}]" value))))

(defn- decode-userinfo [value]
  ;; URLDecoder treats + as a form-space; URI userinfo instead preserves it.
  (URLDecoder/decode (string/replace value "+" "%2B") StandardCharsets/UTF_8))

(defn validate-ca-file!
  "Validate a bounded, explicit PEM CA bundle before opening any connection."
  [value]
  (try
    (when-not (clean-string? value) (invalid!))
    (let [path (Paths/get value (make-array String 0))]
      (when-not (and (.isAbsolute path)
                     (Files/isRegularFile path (make-array LinkOption 0))
                     (Files/isReadable path)
                     (<= 1 (Files/size path) 1048576))
        (invalid!))
      ;; readNBytes keeps the read bounded even if a file changes after stat.
      (let [bytes (with-open [input (Files/newInputStream path (make-array java.nio.file.OpenOption 0))]
                    (.readNBytes input 1048577))
            pem (String. bytes StandardCharsets/US_ASCII)]
        (when-not (and (<= (alength bytes) 1048576)
                       (re-matches #"(?s)\s*(?:-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*)+" pem))
          (invalid!))
        (with-open [input (ByteArrayInputStream. bytes)]
          (let [certs (.generateCertificates (CertificateFactory/getInstance "X.509") input)]
            (when-not (and (<= 1 (count certs) 64)
                           (every? #(and (instance? X509Certificate %)
                                         (>= (.getBasicConstraints ^X509Certificate %) 0)) certs))
              (invalid!)))))
      value)
    (catch Exception _ (invalid!))))

(defn- dedicated-options [db-uri database]
  (try
    (when-not (and (= "production" (:release-mode database))
                   (= "true" (:ssl database))
                   (not (:ignore-ssl database))
                   (clean-string? db-uri))
      (invalid!))
    (let [uri (URI. db-uri)
          host (.getHost uri)
          port (.getPort uri)
          path (.getRawPath uri)
          raw-userinfo (.getRawUserInfo uri)
          credentials (when raw-userinfo (string/split raw-userinfo #":" 2))]
      ;; URL properties take precedence over Properties in pgJDBC. Reject all
      ;; query/fragment options here so a caller cannot replace verification,
      ;; trust, hostname handling, host/user, or driver extension classes.
      (when-not (and (#{"postgres" "postgresql"} (.getScheme uri))
                     (clean-string? host)
                     (or (= -1 port) (<= 1 port 65535))
                     (clean-string? path) (string/starts-with? path "/")
                     (> (count path) 1) (not (string/includes? (subs path 1) "/"))
                     (nil? (.getRawQuery uri)) (nil? (.getRawFragment uri))
                     (= 2 (count credentials)))
        (invalid!))
      (let [[user password] (mapv decode-userinfo credentials)
            host (if (and (string/includes? host ":")
                          (not (string/starts-with? host "["))) (str "[" host "]") host)
            ca (validate-ca-file! (:ssl-ca-file database))]
        (when-not (and (clean-string? user) (clean-string? password)
                       (clean-string? (.getPath uri)))
          (invalid!))
        {:jdbc-url (str "jdbc:postgresql://" host ":" (if (= -1 port) 5432 port) path)
         :username user :password password
         :properties {"sslmode" "verify-full"
                      "sslrootcert" ca
                      "sslfactory" "org.postgresql.ssl.LibPQFactory"
                      "sslhostnameverifier" "org.postgresql.ssl.PGjdbcHostnameVerifier"
                      "gssEncMode" "disable"
                      ;; Disable ambient ~/.postgresql client-key discovery.
                      "sslcert" "" "sslkey" ""}}))
    (catch Exception _ (invalid!))))

(defn connection-options
  "Return connection inputs without constructing a pool or opening sockets.
  An absent dedicated release mode preserves the original upstream URI behavior."
  [db-uri database]
  (if (contains? database :release-mode)
    (dedicated-options db-uri database)
    (let [[_ user password host port db]
          (re-matches #"postgres://(?:(.+):(.*)@)?([^:]+)(?::(\d+))?/(.+)" db-uri)]
      {:jdbc-url (str "jdbc:postgresql://" host ":" (or port 5432) "/" db)
       :username user :password password :properties {}})))
