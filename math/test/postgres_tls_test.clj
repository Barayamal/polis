(ns postgres-tls-test
  (:require [clojure.test :refer :all]
            [clojure.java.io :as io]
            [polismath.components.config :as config]
            [polismath.components.database-tls :as tls]
            [polismath.components.postgres :as postgres])
  (:import (java.nio.file Files)
           (org.postgresql Driver)
           (org.postgresql.ssl LibPQFactory)))

(def ^:dynamic *test-files*)

(use-fixtures :once
  (fn [run-tests]
    (let [dir (.toFile (Files/createTempDirectory "polis-math-tls-" (make-array java.nio.file.attribute.FileAttribute 0)))
          files (into {} (for [name ["ca" "leaf" "empty" "invalid" "oversized" "missing"]]
                           [(keyword name) (io/file dir (str name ".pem"))]))]
      (try
        (doseq [[key resource] [[:ca "fixtures/dedicated-test-ca.pem"]
                               [:leaf "fixtures/dedicated-test-leaf.pem"]]]
          (with-open [input (io/input-stream (io/resource resource))]
            (io/copy input (files key))))
        (spit (files :empty) "")
        (spit (files :invalid) "not a certificate")
        (spit (files :oversized) (apply str (repeat 1048577 "A")))
        (binding [*test-files* (into {} (map (fn [[k f]] [k (.getAbsolutePath f)]) files))]
          (run-tests))
        (finally
          (doseq [f (vals files)] (.delete f))
          (.delete dir))))))

(defn dedicated-config []
  {:release-mode "production" :ssl "true" :ssl-ca-file (*test-files* :ca) :pool-size 1})

(def uri "postgres://reader%40synthetic:p%3Aa+ss@postgres:5432/polis_test")

(defn fixed-rejection? [thunk]
  (try (thunk) false
       (catch clojure.lang.ExceptionInfo e
         (and (= "MATH_DATABASE_TLS_CONFIGURATION_INVALID" (.getMessage e))
              (= {} (ex-data e)) (nil? (.getCause e))))))

(deftest explicit-environment-contract-retains-exact-values
  (is (= {:database {:release-mode "production" :ssl "true"
                    :ssl-ca-file "/run/public-ca.pem" :pool-size 2 :ignore-ssl false}}
         (config/get-environ-config config/rules
           {:fncp-option-c-release-mode "production" :database-ssl "true"
            :database-ssl-ca-file "/run/public-ca.pem" :database-pool-size "2"
            :database-ignore-ssl "false"}))))

(deftest dedicated-effective-driver-settings-authenticate-host-and-ca
  (let [pool (postgres/create-hikari-config uri (dedicated-config))
        effective (Driver/parseURL (.getJdbcUrl pool) (.getDataSourceProperties pool))]
    (is (= "jdbc:postgresql://postgres:5432/polis_test" (.getJdbcUrl pool)))
    (is (= "reader@synthetic" (.getUsername pool)))
    (is (= "p:a+ss" (.getPassword pool)))
    (is (= "verify-full" (.getProperty effective "sslmode")))
    (is (= (*test-files* :ca) (.getProperty effective "sslrootcert")))
    (is (= "org.postgresql.ssl.LibPQFactory" (.getProperty effective "sslfactory")))
    (is (= "org.postgresql.ssl.PGjdbcHostnameVerifier" (.getProperty effective "sslhostnameverifier")))
    (is (= "disable" (.getProperty effective "gssEncMode")))
    (is (= "" (.getProperty effective "sslcert")))
    (is (= "" (.getProperty effective "sslkey")))
    ;; The real driver's CA/key-manager factory must load this explicit bundle.
    ;; Constructing the factory opens no database or network socket.
    (is (instance? LibPQFactory (LibPQFactory. effective)))))

(deftest dedicated-uri-supports-default-port-and-ipv6
  (is (= "jdbc:postgresql://[::1]:5432/polis_test"
         (:jdbc-url (tls/connection-options "postgresql://reader:pw@[::1]/polis_test" (dedicated-config))))))

(deftest dedicated-missing-or-malformed-settings-fail-without-credentials
  (doseq [changes [{:release-mode ""} {:release-mode "false"} {:release-mode "prod"}
                   {:release-mode nil} {:ssl nil} {:ssl false} {:ssl true} {:ssl "false"}
                   {:ssl "TRUE"} {:ignore-ssl true} {:ssl-ca-file nil} {:ssl-ca-file ""}
                   {:ssl-ca-file "relative-ca.pem"}]]
    (is (fixed-rejection? #(postgres/create-hikari-config uri (merge (dedicated-config) changes)))
        (str "Invalid setting keys: " (keys changes)))))

(deftest invalid-ca-material-fails-before-pool-creation
  (doseq [kind [:missing :empty :invalid :leaf :oversized]]
    (is (fixed-rejection? #(postgres/create-hikari-config uri
                            (assoc (dedicated-config) :ssl-ca-file (*test-files* kind))))
        (name kind))))

(deftest uri-properties-cannot-replace-verification-or-load-driver-extensions
  (doseq [query ["sslmode=disable" "sslmode=prefer" "sslmode=require" "sslmode=verify-ca"
                 "sslmode=verify-full&sslmode=disable" "%73slmode=disable"
                 "sslfactory=org.postgresql.ssl.NonValidatingFactory"
                 "sslhostnameverifier=custom.Verifier" "sslrootcert=/different/ca.pem"
                 "user=other&password=other" "socketFactory=custom.Factory" "options=-c%20x=y"]]
    (is (fixed-rejection? #(postgres/create-hikari-config (str uri "?" query) (dedicated-config))))))

(deftest invalid-uris-do-not-expose-credentials-or-open-pools
  (doseq [url ["not a uri" "http://reader:password@postgres/polis_test"
               "postgres://reader:password@postgres:0/polis_test"
               "postgres://reader:password@postgres:65536/polis_test"
               "postgres://reader:password@postgres/" "postgres://reader:password@postgres/a/b"
               "postgres://reader:password@postgres/polis_test#fragment"
               "postgres://reader@postgres/polis_test" "postgres://:password@postgres/polis_test"
               "postgres://reader:@postgres/polis_test" "postgres://reader:p%0Ass@postgres/polis_test"
               "postgres://reader:password@postgres/polis%0atest"]]
    (is (fixed-rejection? #(postgres/create-hikari-config url (dedicated-config))))))

(deftest ordinary-upstream-configuration-retains-prior-driver-options
  (let [ordinary-uri "postgres://reader:password@localhost/polis_test?sslmode=disable"
        pool (postgres/create-hikari-config ordinary-uri {:pool-size 1 :ignore-ssl true})
        effective (Driver/parseURL (.getJdbcUrl pool) (.getDataSourceProperties pool))]
    (is (= "jdbc:postgresql://localhost:5432/polis_test?sslmode=disable" (.getJdbcUrl pool)))
    (is (= "disable" (.getProperty effective "sslmode")))
    (is (nil? (.getProperty effective "sslrootcert")))))
