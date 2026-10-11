(ns dedicated-analysis-test
  (:require [clojure.test :refer :all]
            [clojure.java.io :as io]
            [cheshire.core :as json]
            [clojure.core.matrix :as matrix]
            [com.stuartsierra.component :as component]
            [polismath.components.core-matrix-boot :as matrix-boot]
            [polismath.math.conversation :as conv]
            [polismath.conv-man :as manager])
  (:import (java.util Random)))

(use-fixtures :once
  (fn [run-tests]
    ;; Production startup installs the matrix JSON encoders before polling.
    (let [booter (component/start (matrix-boot/create-core-matrix-booter
                                   {:config {:math {:matrix-implementation :vectorz}}}))]
      (try (run-tests) (finally (component/stop booter))))))

(def fixture (json/parse-string (slurp (io/resource "fixtures/dedicated-analysis.json")) true))
(defn votes []
  (vec (for [pid (range (:participantCount fixture)) tid (range (:statementCount fixture))]
    {:zid 1 :pid pid :tid tid :created (+ 1000 (* pid 15) tid)
     :vote (get-in fixture [:profiles (quot pid (:cohortSize fixture)) tid])})))
(defn finite-values? [x] (every? #(Double/isFinite (double %)) (matrix/eseq x)))

(deftest synthetic-eighteen-participant-fixture-computes-real-analysis
  ;; Inputs and the PCA starting-vector stream are repeatable. Assertions use
  ;; stable invariants; PCA signs and group labels are not a public contract.
  (doseq [seed [1409 1410]]
    (let [random (Random. seed)
          initial (conv/mod-update (assoc (conv/new-conv) :zid 1)
                    (mapv (fn [tid] {:tid tid :mod 1 :is_meta false :modified 900}) (range 15)))
          result (with-redefs [clojure.core/rand (fn ([] (.nextDouble random)) ([n] (* n (.nextDouble random))))]
                   (let [computed (conv/conv-update initial (votes))]
                     ;; The parallel graph returns deferred values. Keep the
                     ;; seeded starting-vector scope until every checked math
                     ;; dependency has actually completed.
                     (json/generate-string (manager/prep-main computed))
                     (dorun (matrix/eseq (:proj computed)))
                     computed))
          pca (:pca result)
          base-by-id (into {} (map (juxt :id :members) (:base-clusters result)))
          group-pids (mapcat (fn [group] (mapcat base-by-id (:members group))) (:group-clusters result))
          main (manager/prep-main result)]
      (is (= 18 (:n result))) (is (= 15 (:n-cmts result)))
      (is (= (set (range 15)) (set (:tids result))))
      (is (= (set (range 18)) (:in-conv result)))
      (is (= #{15} (set (vals (:user-vote-counts result)))))
      (is (= #{} (:mod-out result))) (is (= (set (range 15)) (:mod-in result)))
      (is (= 2 (count (:comps pca))))
      (is (= [2 15] (matrix/shape (:comps pca))))
      (is (= [15] (matrix/shape (:center pca))))
      (is (finite-values? (:center pca))) (is (finite-values? (:comps pca)))
      (is (= [18 2] (matrix/shape (:proj result))))
      (is (finite-values? (:proj result)))
      (is (<= 2 (count (:group-clusters result)) 5))
      (is (= 18 (count group-pids))) (is (= (set (range 18)) (set group-pids)))
      (doseq [tid (range 15)]
        (let [per-group (map #(get-in % [:votes tid]) (vals (:group-votes result)))
              agree (reduce + (map :A per-group))
              disagree (reduce + (map :D per-group))
              seen (reduce + (map :S per-group))]
          (is (= 18 seen (+ agree disagree)))
          (is (= (if (<= 5 tid 9) 12 6) agree))))
      (is (= 1269 (:lastVoteTimestamp main)))
      (is (= 900 (:lastModTimestamp main)))
      (is (= 18 (:n main)))
      (is (= 15 (count (:comment-priorities main))))
      (is (seq (:base-clusters main)))
      (is (seq (:group-clusters main)))
      (is (= 18 (:n (json/parse-string (json/generate-string main) true)))))))
