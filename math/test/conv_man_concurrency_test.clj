(ns conv-man-concurrency-test
  (:require [clojure.test :refer :all]
            [clojure.core.async :as async]
            [polismath.conv-man :as manager]
            [polismath.components.postgres :as postgres]))

(defn start-thread [f]
  (let [done (promise)
        thread (Thread. (fn [] (try (deliver done {:result (f)})
                                   (catch Throwable e (deliver done {:error e})))))]
    (.setDaemon thread true)
    (.start thread)
    {:thread thread :done done}))

(defn wait-until [condition]
  (let [deadline (+ (System/nanoTime) 5000000000)]
    (loop []
      (cond (condition) true
            (> (System/nanoTime) deadline) false
            :else (do (Thread/sleep 1) (recur))))))

(deftest concurrent-first-vote-and-moderation-batches-share-one-actor
  (let [entered (promise), release (promise), created (atom [])
        conversations (atom {})
        component {:conversations conversations :kill-chan (async/promise-chan)}]
    (with-redefs [manager/conv-actor
                  (fn [_ zid]
                    (let [actor {:zid zid :message-chan (async/chan 10)}
                          count-created (count (swap! created conj actor))]
                      (when (= 1 count-created)
                        (deliver entered true)
                        (when (= ::timeout (deref release 10000 ::timeout))
                          (throw (Exception. "ACTOR_TEST_RELEASE_TIMEOUT"))))
                      actor))]
      (let [first-call (start-thread #(manager/queue-message-batch! component :votes 1 [{:pid 1}]))]
        (try
          (is (= true (deref entered 5000 ::timeout)))
          (let [second-call (start-thread #(manager/queue-message-batch! component :moderation 1 [{:tid 1 :mod 1}]))]
            (try
              ;; With the old check-then-create path the second constructor
              ;; completes while the first is held; with the fix it blocks on
              ;; the creation monitor. Both outcomes are directly observable.
              (is (wait-until #(or (realized? (:done second-call))
                                  (= "BLOCKED" (str (.getState ^Thread (:thread second-call)))))))
              (is (= 1 (count @created)))
              (finally (deliver release true)))
            (is (not= ::timeout (deref (:done second-call) 5000 ::timeout)))
            (is (nil? (:error (deref (:done second-call) 0 {:error ::timeout})))))
          (is (not= ::timeout (deref (:done first-call) 5000 ::timeout)))
          (is (nil? (:error (deref (:done first-call) 0 {:error ::timeout}))))
          (is (= 1 (count @created)))
          (let [channel (:message-chan (get @conversations 1))
                messages [(async/poll! channel) (async/poll! channel)]]
            (is (= #{:votes :moderation} (set (map :message-type messages)))))
          (finally
            (deliver release true)
            (doseq [actor @created] (async/close! (:message-chan actor)))
            (async/close! (:kill-chan component))))))))

(deftest persistence-completes-in-actor-order-and-propagates-write-errors
  (let [calls (atom [])
        component {:postgres ::fake}
        result {:zid 1 :last-vote-timestamp 123 :base-clusters [] :ptpt-stats []}
        upload (fn [table] (fn [_ _ tick _] (swap! calls conj [tick table])))]
    (with-redefs [postgres/upload-math-main (upload :main)
                  postgres/upload-math-bidtopid (upload :bidtopid)
                  postgres/upload-math-ptptstats (upload :ptptstats)]
      (manager/write-conv-updates! component result 1)
      (is (= [[1 :main] [1 :bidtopid] [1 :ptptstats]] @calls))
      (manager/write-conv-updates! component result 2)
      (is (= [[1 :main] [1 :bidtopid] [1 :ptptstats]
              [2 :main] [2 :bidtopid] [2 :ptptstats]] @calls)))
    ;; An asynchronous writer used to discard this error outside the actor's
    ;; existing retry handler. The caller must receive it before proceeding.
    (with-redefs [postgres/upload-math-main (fn [& _] (throw (Exception. "PERSISTENCE_TEST_FAILURE")))]
      (is (thrown-with-msg? Exception #"PERSISTENCE_TEST_FAILURE"
                           (manager/write-conv-updates! component result 3))))))

(deftest failed-write-is-replayed-with-the-next-vote-batch
  (let [kill (async/promise-chan), messages (async/chan 10), retry (async/chan 10)
        initial {:zid 1 :n 0 :applied [] :last-vote-timestamp 0 :base-clusters [] :ptpt-stats []}
        state (atom initial), first-vote {:pid 1 :tid 0 :vote -1 :created 1}
        next-vote {:pid 2 :tid 0 :vote 1 :created 2}
        actor {:zid 1 :conv state :message-chan messages :retry-chan retry}
        component {:kill-chan kill :postgres ::fake}
        attempted (atom 0), tick (atom 0), failed (promise), persisted (promise)]
    (with-redefs [manager/conv-update
                  (fn [_ conv votes]
                    (let [applied (into (:applied conv) votes)]
                      (assoc conv :applied applied :n (count applied) :last-vote-timestamp (apply max (map :created applied)))))
                  postgres/inc-math-tick (fn [& _] (swap! tick inc))
                  postgres/upload-math-main
                  (fn [& _] (when (= 1 (swap! attempted inc)) (throw (Exception. "FIRST_WRITE_RETRY_TEST"))))
                  postgres/upload-math-bidtopid (fn [& _] nil)
                  postgres/upload-math-ptptstats (fn [& _] (deliver persisted true))
                  ;; Preserve the production retry-message shape, while keeping
                  ;; notification and diagnostic file side effects out of tests.
                  manager/handle-errors
                  (fn [_ actor _ type batch _ _]
                    (async/>!! (:retry-chan actor) {:message-type type :message-batch batch})
                    (deliver failed true))]
      (let [loop-done (manager/go-act! component actor)]
        (try
          (async/>!! messages {:message-type :votes :message-batch [first-vote]})
          (is (= true (deref failed 5000 ::timeout)))
          (is (= [] (:applied @state)))
          (async/>!! messages {:message-type :votes :message-batch [next-vote]})
          (is (= true (deref persisted 5000 ::timeout)))
          (is (wait-until #(= 2 (:n @state))))
          (is (= [first-vote next-vote] (:applied @state)))
          (is (= 2 @attempted))
          (finally
            (async/close! kill)
            (is (= loop-done (second (async/alts!! [loop-done (async/timeout 5000)]))))
            (async/close! messages)
            (async/close! retry)))))))
