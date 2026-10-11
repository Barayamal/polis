(ns export-test
  (:require [clojure.test :refer :all]
            [polismath.darwin.export :as export]))

(deftest vectorize-preserves-explicit-column-order
  (is (= [["Second" "First"]
          [2 1]
          [4 3]]
         (vec (export/vectorize
                {:header [:second :first]
                 :format-header {:first "First" :second "Second"}}
                [{:first 1 :second 2}
                 {:first 3 :second 4}])))))

(deftest vectorize-supports-the-former-semantic-csv-options
  (testing "the default header strips keyword colons"
    (is (= [["first" "second"] [1 2]]
           (vec (export/vectorize [{:first 1 :second 2}])))))
  (testing "the header can be suppressed without changing value order"
    (is (= [[2 1]]
           (vec (export/vectorize
                  {:header [:second :first]
                   :prepend-header false}
                  [{:first 1 :second 2}])))))
  (testing "a false format-header leaves keywords unchanged"
    (is (= [[:first] [1]]
           (vec (export/vectorize
                  {:header [:first]
                   :format-header false}
                  [{:first 1}]))))))
