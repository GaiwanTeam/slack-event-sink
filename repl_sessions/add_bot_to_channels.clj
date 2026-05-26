(ns add-bot-to-channels
  (:require
   [co.gaiwan.slack-event-sink :as event-sink]
   [co.gaiwan.slack.api :as slack]
   [co.gaiwan.slack.api.middleware :as mw]
   [lambdaisland.config :as config]
   ))

(config/reload! event-sink/config)

(defn conn []
  (slack/conn (config/get event-sink/config :slack/bot-token)))

#_(def invite (slack/post-endpoint "admin.conversations.invite"))
(def invite (slack/post-endpoint "conversations.invite"))
(def join (mw/wrap-rate-limit (slack/post-endpoint "conversations.join")))

(def users
  (slack/users (conn)))

(def logbot (:user/id (first (filter (comp #{"logbot"} :user/name) users))))
(def logbot2 (:user/id (first (filter (comp #{"logbot2"} :user/name) users))))

(def channels (slack/conversations (conn)))

(def members (slack/collection-endpoint :members "conversations.members"))

(def channel-members
  (into {}
        (for [{cid :channel/id} channels]
          [cid (members (conn) {:channel cid})])))

(set! *print-namespace-maps* false)

(def channels-to-invite
  (filter (fn [{cid :channel/id}]
            (let [members (channel-members cid)]
              (and (some #{logbot} members)
                   (not (some #{logbot2} members)))))
          channels))

(doseq [{cid :channel/id
         cname :channel/name} (drop-while #(< (compare (:channel/name %) "hispano") 0) (sort-by :channel/name channels-to-invite))]
  (println cid '- cname)
  (join (conn) {:channel cid}))




https://app.slack.com/client/T03RZGPFR/C03RZMDSH
