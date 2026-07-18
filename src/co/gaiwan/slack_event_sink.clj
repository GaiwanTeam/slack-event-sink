(ns co.gaiwan.slack-event-sink
  "Receive events from slack, store them in files"
  (:require
   [charred.api :as charred]
   [clojure.java.io :as io]
   [clojure.pprint :as pprint]
   [clojure.string :as str]
   [co.gaiwan.slack.api :as slack]
   [co.gaiwan.slack.raw-event :as raw-event]
   [co.gaiwan.slack.time-util :as time-util]
   [hato.client :as hato]
   [io.pedestal.log :as log]
   [lambdaisland.cli :as cli]
   [lambdaisland.config :as config]
   [lambdaisland.config.cli :as config-cli]
   [lambdaisland.makina.app :as app]
   [ring.adapter.jetty :as jetty]
   [ring.util.request :as req])
  (:import
   (java.net StandardProtocolFamily UnixDomainSocketAddress)
   (java.nio ByteBuffer)
   (java.nio.channels SelectionKey Selector ServerSocketChannel SocketChannel)
   (javax.crypto Mac)
   (javax.crypto.spec SecretKeySpec)))

(set! *warn-on-reflection* true)

(def config
  (-> (config/create {:prefix "slack-event-sink"})
      config-cli/add-provider))

(def ^Mac hmac-sha-256 (Mac/getInstance "HMACSHA256"))

(defn signature [^SecretKeySpec signing-key ^String body]
  (apply str
         (map #(format "%02x" %)
              (.doFinal (doto hmac-sha-256
                          (.init signing-key)
                          (.update (.getBytes body)))))))

(defn header [req h]
  (get-in req [:headers h]))

(defn wrap-body-params [f ^SecretKeySpec signing-key]
  (fn [req]
    (let [body      (slurp (:body req))
          slack-sig (header req "x-slack-signature")
          slack-ts  (some-> (header req "x-slack-request-timestamp") parse-long)
          now-ts    (long (/ (System/currentTimeMillis) 1000))
          sig       (signature signing-key (str "v0:" slack-ts ":" body))]
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
        (let [body-params (charred/read-json body)]
          (f (-> req
                 (assoc :body-str body)
                 (assoc :body-params body-params))))))))

(defn wrap-log-req [f opts]
  (if (:verbose opts)
    (fn [req]
      (try
        (println "------------------------------")
        (println
         (str/upper-case (symbol (:request-method req)))
         (:uri req))
        (pprint/pprint req)
        (let [res (f req)]
          (println "----")
          (pprint/pprint res)
          res)
        (catch Throwable e
          (println "ERROR" e)
          {:status 200})))
    (fn [req]
      (try
        (let [res (f req)]
          (println
           (str/upper-case (symbol (:request-method req)))
           (:uri req)
           (:status res)
           (str "type=" (get-in req [:body-params "event" "type"]))
           (str "event_ts=" (get-in req [:body-params "event" "event_ts"])))
          res)
        (catch Throwable e
          (println "ERROR" e)
          {:status 200})))))

(def file-info (slack/simple-endpoint "files.info"))

(defn archive-json-path [team-id e]
  (when team-id
    (let [ts (raw-event/message-ts e)
          day (time-util/format-inst-day (time-util/ts->inst ts))]
      (str team-id "/" (or (raw-event/channel-id e) "META") "/" day ".jsonl"))))

(defn download-file! [bot-token archive-path team-id id]
  (let [info (file-info (slack/conn bot-token)
                        {:file id})
        info-file (io/file archive-path
                           (str team-id "/FILES/" id ".json"))
        data-file (io/file archive-path
                           (str team-id "/FILES/" id))
        url (get-in info ["file" "url_private_download"])]
    (io/make-parents info-file)
    (spit info-file (charred/write-json-str info))
    (println "Downloading" url "to" data-file)
    (with-open [f (io/output-stream data-file)]
      (io/copy
       (:body (hato/get url {:as :stream
                             :oauth-token bot-token}))
       data-file))))

(defn make-handler [event-handlers]
  (fn [req]
    (let [{:keys [body-params]} req
          {:strs [type challenge]} body-params]
      (if (= "url_verification" type)
        {:status 200
         :headers {"content-type" "text/plain"}
         :body challenge}
        (let [errors? (volatile! false)]
          (doseq [h event-handlers]
            (try
              (h req)
              (catch Throwable e
                (log/error :event-handler/failed {} :exception e)
                (vreset! errors? true))))
          (if @errors?
            {:status 500}
            {:status 200}))))))

(def archive-handler
  {:start
   (fn [{:keys [archive-path bot-token]}]
     (fn [req]
       (let [{:strs [event team_id]} (:body-params req)]
         (if-let [ts (raw-event/message-ts event)]
           (let [file (io/file archive-path
                               (archive-json-path team_id event))]
             (when file
               (io/make-parents file)
               (spit file (str (charred/write-json-str event) "\n") :append true))
             (when (= "file_shared" (raw-event/type event))
               (future
                 (download-file! bot-token archive-path team_id (get-in event ["file" "id"])))))
           (println "No timestamp:" (pr-str (:body-params req)))))))
   :stop identity})

(defn start-unix-socket [socket-path state]
  (future
    (try
      (log/info :unix-socket/starting {:path socket-path})
      (let  [path        (java.nio.file.Path/of socket-path (into-array String []))
             _           (.delete (.toFile path))
             addr        (UnixDomainSocketAddress/of path)
             server-chan (ServerSocketChannel/open StandardProtocolFamily/UNIX)
             selector    (Selector/open)]
        (.bind server-chan addr)
        (.configureBlocking server-chan false)
        (.register server-chan selector SelectionKey/OP_ACCEPT)
        (while true
          (let [n (.select selector)]
            (when (pos? n)
              (let [selected (java.util.ArrayList. (.selectedKeys selector))]
                (.clear (.selectedKeys selector))
                (doseq [^SelectionKey key selected]
                  (when (.isValid key)
                    (try
                      (cond
                        (.isAcceptable key)
                        (let [server ^ServerSocketChannel (.channel key)
                              client ^SocketChannel (.accept server)]
                          (.configureBlocking client false)
                          (.register client selector SelectionKey/OP_READ)
                          (let [[{:keys [buffer]}]
                                (swap-vals! state
                                            (fn [s] (-> s
                                                        (assoc :buffer [])
                                                        (update :clients conj client))))]
                            (doseq [msg buffer]
                              (try
                                (.write client (ByteBuffer/wrap (.getBytes ^String msg "UTF-8")))
                                (catch Exception e
                                  (log/error :unix-socket/flush-failed {} :exception e))))))

                        (.isReadable key)
                        (let [client ^SocketChannel (.channel key)
                              buf (ByteBuffer/allocate 1)]
                          (when (= -1 (.read client buf))
                            (.cancel key)
                            (.close client)
                            (swap! state update :clients disj client))))
                      (catch Exception e
                        (log/error :unix-socket/selector-failed {} :exception e)
                        (.cancel key)
                        (when-let [ch (.channel key)]
                          (.close ch)
                          (swap! state update :clients disj ch)))))))))))
      (catch Exception e
        (log/error :unix-socket/main-loop-broke {} :exception e)))))

(def unix-socket-handler
  {:start
   (fn [{:keys [socket-path]}]
     (if-not socket-path
       identity
       (let [state (atom {:clients #{} :buffer []})]
         (start-unix-socket socket-path state)
         (fn [req]
           (let [{:keys [clients]} @state]
             (if (seq clients)
               (doseq [^SocketChannel c clients]
                 (try
                   (.write c (ByteBuffer/wrap (.getBytes ^String (:body-str req) "UTF-8")))
                   (catch Exception e
                     (log/error :unix-socket/write-failed {} :exception e)
                     (swap! state update :clients disj c))))
               (swap! state update :buffer conj (:body-str req))))))))})

(def http-server
  {:start
   (fn [{:keys [port verbose event-handlers signing-secret]}]
     (let [signing-key (SecretKeySpec.
                        (.getBytes ^String signing-secret)
                        (.getAlgorithm hmac-sha-256))]
       (log/info :http/starting {:port port})
       (jetty/run-jetty
        (-> (make-handler event-handlers)
            (wrap-log-req {:verbose verbose})
            (wrap-body-params signing-key))
        {:port port
         :join? false})))
   :stop
   (fn [server]
     (when server
       (.stop ^org.eclipse.jetty.server.Server server)))})

(defonce system
  (app/create
   {:prefix "slack-event-sink"
    :data-readers {'config (partial config/get config)}}))

(defn start!
  "Start Slack-event-sink"
  [& _]
  (app/start! system))

(def cmdspec
  {:name "slack-event-sink"
   :doc "Listen for events from Slack coming in through the Event API and captures them.

         Events are stored in JSONL files in  a channel/date hierarchy."
   :commands
   ["start" #'start!]
   :flags
   ["--port <port>" {:key :http/port
                     :doc "HTTP port to listen on"}
    "--path <path>"  {:key :archive/path
                      :doc "Location where the write the archive (directory)"}
    "--bot-token <token>" {:key :slack/bot-token
                           :doc "Slack bot token"}
    "--signing-secret <secret>" {:key :slack/signing-secret
                                 :doc "Slack signing secret"}
    "--verbose,-v" {:key :verbose
                    :doc "Increase verbosity"}]})

(defn -main [& argv]
  (cli/dispatch* cmdspec argv))

(comment
  (start!)
  (stop!))
