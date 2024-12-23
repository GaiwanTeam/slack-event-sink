(ns co.gaiwan.slack-event-sink
  (:require
   [charred.api :as charred]
   [clojure.java.io :as io]
   [co.gaiwan.slack.api :as slack]
   [co.gaiwan.slack.raw-event :as raw-event]
   [co.gaiwan.slack.time-util :as time-util]
   [hato.client :as hato]
   [io.pedestal.log :as log]
   [lambdaisland.cli :as cli]
   [lambdaisland.config :as config]
   [lambdaisland.config.cli :as config-cli]
   [ring.adapter.jetty :as jetty]
   [ring.util.request :as req])
  (:import
   (javax.crypto Mac)
   (javax.crypto.spec SecretKeySpec)))

(set! *warn-on-reflection* true)

(def config
  (-> (config/create {:prefix "slack-event-sink"})
      config-cli/add-provider))

(def ^Mac hmac-sha-256 (Mac/getInstance "HMACSHA256"))

(def signing-key
  (delay
    (SecretKeySpec.
     (.getBytes ^String (config/get config :slack/signing-secret))
     (.getAlgorithm hmac-sha-256))))

(defn signature [^String body]
  (apply str
         (map #(format "%02x" %)
              (.doFinal (doto hmac-sha-256
                          (.init @signing-key)
                          (.update (.getBytes body)))))))

(defn header [req h]
  (get-in req [:headers h]))

(defn wrap-body-params [f]
  (fn [req]
    (def rr req)
    (let [body      (slurp (:body req))
          slack-sig (header req "x-slack-signature")
          slack-ts  (some-> (header req "x-slack-request-timestamp") parse-long)
          now-ts    (long (/ (System/currentTimeMillis) 1000))
          sig       (signature (str "v0:" slack-ts ":" body))]
      (cond
        (not= (str "v0=" sig) slack-sig)
        {:status 403
         :body "signature mismatch"}

        (or (not slack-ts)
            (< 2 (Math/abs (- now-ts (long slack-ts)))))
        {:status 403
         :body "timestamp mismatch"}

        (not= "application/json" (req/content-type req))
        {:status 415
         :body "content-type must be application/json"}

        :else
        (f (assoc req :body-params (charred/read-json body)))))))

(defn wrap-log-req [f]
  (fn [req]
    (try
      (let [res (f req)]
        (println
         (get-in req [:body-params "event" "event_ts"])
         (get-in req [:body-params "event" "type"])
         (:status res))
        res)
      (catch Throwable e
        (println "ERROR" e)
        {:status 200}))))

(def file-info (slack/simple-endpoint "files.info"))

(defn archive-json-path [team-id e]
  (when team-id
    (let [ts (raw-event/message-ts e)
          day (time-util/format-inst-day(time-util/ts->inst  "1734425456.329100"))]
      (str team-id "/" (or (raw-event/channel-id e) "META") "/" day ".jsonl"))))

(defn download-file! [team-id id]
  (let [info (file-info (slack/conn (config/get config :slack/bot-token))
                        {:file id})
        info-file (io/file (config/get config :archive/path)
                           (str team-id "/FILES/" id ".json"))
        data-file (io/file (config/get config :archive/path)
                           (str team-id "/FILES/" id))
        url (get-in info ["file" "url_private_download"])]
    (io/make-parents info-file)
    (spit info-file (charred/write-json-str info))
    (with-open [f (io/output-stream data-file)]
      (io/copy
       (:body (hato/get url {:as :stream
                             :oauth-token (config/get config :slack/bot-token)}))
       data-file))))

(defn handler [{:keys [body-params] :as req}]
  (let [{:strs [event team_id type token challenge]} body-params]
    (if (= "url_verification" type)
      {:status 200
       :headers {"content-type" "text/plain"}
       :body challenge}
      (let [ts (raw-event/message-ts event)
            file (io/file (config/get config :archive/path)
                          (archive-json-path team_id event))]
        (when file
          (io/make-parents file)
          (spit file (str (charred/write-json-str event) "\n") :append true))
        (when (= "file_shared" (raw-event/type event))
          (future
            (download-file! team_id (get-in event ["file" "id"]))))
        {:status 200}))))

(defonce jetty nil)

(defn start! [opts]
  (let [port (config/get config :http/port)
        path (config/get config :archive/path)]
    (log/info :http/starting {:port port
                              :path path})
    (log/info :bot-token/source (config/source config :slack/bot-token))
    (log/info :signing-secret/source (config/source config :slack/signing-secret))
    (alter-var-root
     #'jetty
     (fn [jetty]
       (when jetty
         (.stop ^org.eclipse.jetty.server.Server jetty))
       (jetty/run-jetty
        (-> #'handler
            wrap-log-req
            wrap-body-params)
        {:port (config/get config :http/port)
         :join? false})))))

(def cmdspec
  {:name "slack-event-sink"
   :doc "Listen for events from Slack coming in through the Event API and captures them.

         Events are stored in JSONL files in  a channel/date hierarchy."
   :commands
   ["start <slack/signing-secret>" #'start!
    "inspect  <slack/signing-secret>" #'prn]
   :flags
   ["--port <port>" {:key :http/port
                     :doc "HTTP port to listen on"}
    "--path <path>"  {:key :archive/path
                      :doc "Location where the write the archive (directory)"}
    "--bot-token <token>" {:key :slack/bot-token
                           :doc "Slack bot token"}
    "--signing-secret <secret>" {:key :slack/signing-secret
                                 :doc "Slack signing secret"}]})

(defn -main [& argv]
  (cli/dispatch* cmdspec argv))
