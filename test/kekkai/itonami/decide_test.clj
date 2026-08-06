(ns kekkai.itonami.decide-test
  "The paid resource. What is asserted here is that it is a pass-through: the
  answers must be the ones `kekkai.acl/edge-decision` gives, because a policy
  engine that disagrees with the governor is worse than none."
  (:require [clojure.test :refer [deftest is testing]]
            [kekkai.acl :as acl]
            [kekkai.itonami.decide :as decide]))

(def policies
  {"default"
   {:tag-owners {"tag:server" ["alice"] "tag:laptop" ["alice"]}
    :grants [{:src ["tag:laptop"] :dst ["tag:server"] :ports [22]
              :capabilities [:overlay :ssh]}]}
   "acme"
   {:tag-owners {"tag:cache" ["bob"]}
    :grants [{:src ["bob"] :dst ["tag:cache"] :ports ["*"]}]}})

(def laptop {:id "n-laptop" :user "alice" :tailnet "default" :tags ["tag:laptop"]})
(def server {:id "n-server" :user "alice" :tailnet "default" :tags ["tag:server"]})
(def cache  {:id "a-cache"  :user "bob"   :tailnet "acme"    :tags ["tag:cache"]})

(defn- request
  ([src dst] (request src dst []))
  ([src dst peerings]
   {:plane {:policies policies :peerings peerings} :src src :dst dst}))

(deftest an-allowed-edge-carries-the-grant-that-allowed-it
  (let [r (decide/decide (request laptop server))]
    (is (true? (:allowed? r)))
    (is (= [22] (:ports r)))
    (is (= [:overlay :ssh] (:capabilities r)))
    (is (= :policy (:via r)))
    (is (= "default" (:src-tailnet r)))))

(deftest the-three-refusals-stay-distinct
  (testing "same tailnet, no grant -> :deny-by-default (a policy edit)"
    (is (= :deny-by-default (:reason (decide/decide (request server laptop))))))
  (testing "different tailnets, no peering -> :cross-tailnet (a negotiation)"
    (is (= :cross-tailnet (:reason (decide/decide (request laptop cache))))))
  (testing "peered, but not for this edge -> :peering-grant-missing"
    (let [peering {:id "p" :a "default" :b "acme" :status "active"
                   :approved-by ["default" "acme"]
                   :grants [{:from "default" :src ["nobody"] :dst ["tag:cache"]
                             :ports [443]}]}]
      (is (= :peering-grant-missing
             (:reason (decide/decide (request laptop cache [peering]))))))))

(deftest a-mutually-approved-peering-allows-the-edge
  (let [peering {:id "p" :a "default" :b "acme" :status "active"
                 :approved-by ["default" "acme"]
                 :grants [{:from "default" :src ["tag:laptop"] :dst ["tag:cache"]
                           :ports [443]}]}
        r (decide/decide (request laptop cache [peering]))]
    (is (true? (:allowed? r)))
    (is (= :peering (:via r)))
    (is (= "p" (:peering r))))
  (testing "one-sided approval carries nothing"
    (let [peering {:id "p" :a "default" :b "acme" :status "active"
                   :approved-by ["acme"]
                   :grants [{:from "default" :src ["tag:laptop"] :dst ["tag:cache"]
                             :ports [443]}]}]
      (is (= :cross-tailnet
             (:reason (decide/decide (request laptop cache [peering]))))))))

(deftest the-answer-is-exactly-the-governors-answer
  (testing "no second policy engine: every field edge-decision returns survives"
    (doseq [[src dst] [[laptop server] [server laptop] [laptop cache]]]
      (let [plane {:policies policies :peerings []}
            direct (acl/edge-decision plane src dst)
            served (decide/decide (request src dst))]
        (is (= direct (select-keys served (keys direct)))
            (str (:id src) " -> " (:id dst)))))))

(deftest a-self-claimed-tag-is-reported-alongside-an-allow
  (testing "an allow can hide an escalation: the grant matched a tag its owner
            was never authorised to assume"
    (let [rogue {:id "n-rogue" :user "mallory" :tailnet "default"
                 :tags ["tag:server"]}
          r (decide/decide (request laptop rogue))]
      (is (true? (:allowed? r)) "the grant does match")
      (is (= [] (:src-unowned-tags r)) "the laptop's own tags are owned")
      (is (= ["tag:server"]
             (:src-unowned-tags (decide/decide (request rogue laptop))))
          "and mallory's claim on tag:server is not"))))

(deftest a-malformed-request-is-refused-with-every-problem-at-once
  (let [r (decide/decide {:plane "not a map" :src nil :dst {}})]
    (is (= :invalid-request (:error r)))
    (is (= #{:plane-not-a-map :src-not-a-node :dst-missing-id}
           (set (map :problem (:problems r))))))
  (testing "each round trip past a 402 is a payment, so they come together"
    (is (< 1 (count (:problems (decide/decide {:plane {} :src nil :dst nil})))))))
