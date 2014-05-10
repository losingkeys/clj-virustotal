(ns clj-virustotal.core
  "Generic functions for working VirusTotal's API

More information:
https://www.virustotal.com/en/documentation/public-api/"
  (:require [clj-http.client :as http]
            [digest]
            [clojure.string :as s]
            [cheshire.core :as json]))

(def  VT_HTTP_OPTIONS
  "Any extra HTTP options to pass to clj-http. See its usage for more info:
https://github.com/dakrone/clj-http#usage"
  {:throw-exceptions false})

(def VT_API_BASE_URL
  "The BASE URL of VirusTotal's HTTP API"
  (or (System/getenv "VT_API_BASE_URL")
      "https://www.virustotal.com/vtapi/v2/"))

(def VT_API_KEY
  "Your VirusTotal API key. After logging in, go the following page to copy it:
https://www.virustotal.com/en/user/<your username>/apikey/

Note: this can be set as the VT_API_KEY environment variable."
  (or (System/getenv "VT_API_KEY")
      "please set the 'VT_API_KEY' environment variable to your VirusTotal API key"))

(defn- url-from-path
  "Returns a valid VirusTotal API URL given a relative path. Removes
  duplicate '/'characters

Arguments:

- path: the relative path of a VirusTotal URL"
  {:added "2.0"}
  [path]
  (s/replace-first (s/replace (str VT_API_BASE_URL path)
                              #"/+" "/")
                   "/" "//"))

(defn- add-api-key-to-multipart-map
  "Adds your VirusTotal API key to the 'multipart' vector of a generic
  map (this format is used by clj-http to send multipart http requests)

Arguments:

- m: a hash-map with a :multipart key that points to a vector. The
  VirusTotal API key will be added to this vector

For instance, given a map in the format:

{:multipart [...]}

Returns a map in the format:

{:multipart [{:name \"apikey\" :content \"Your VirusTotal API key here\"}
             ...]}

For more info on clj-http's multipart requests, see the 'usage' section
of the README:
https://github.com/dakrone/clj-http#usage

For more information on the request format for VirusTotal API requests,
see the intro to its API documentation:
https://www.virustotal.com/en/documentation/public-api/"
  {:added "2.0"}
  [m]
  (let [v (:multipart m)]
    (assoc m
      :multipart (conj v {:name "apikey" :content VT_API_KEY}))))

(defn- make-multipart-map
  "Transform the given map a map in the format needed by clj-http to
  make multipart http requests

For more info on clj-https' multipart requests, see the 'usage' section
of the README:
https://github.com/dakrone/clj-http#usage"
  {:added "2.0"}
  [m]
  {:multipart (reduce (fn [memo [k v]]
                        (conj memo {:name (subs (str k) 1)
                                    :content v}))
                      []
                      m)})

(defn- parse-and-replace-json-body
  "Parse the string in the :body key of the given map as json. Returns
  the map with the newly parsed body. The JSON keys are lowercase
  symbols with non-alphanumeric characters replaced with dash '-'
  characters

Arguments:

- response: a hash-map containing a :body key pointing to a JSON string"
  {:added "2.0"}
  [response]
  (let [body (:body response)
        parsed (json/parse-string body #(keyword (.toLowerCase (s/replace % #"[\W_]+" "-"))))]
    (assoc response :body parsed)))

(defn api-post-generic
  "Make a generic HTTP POST request to VirusTotal's API.

Arguments:

- path: the relative path of the URL to request

- param-map: a hash-map of parameters to send along with the
  request. Your VirusTotal API key will be added to this map"
  {:added "2.0"}
  [path param-map]
  (parse-and-replace-json-body (http/post (url-from-path path)
                                          (merge (add-api-key-to-multipart-map param-map)
                                                 VT_HTTP_OPTIONS))))

(defn api-post
  "Make an HTTP POST request to VirusTotal's API

Arguments:

- path: the relative path of the URL to request

- param-map: keys and values to send as parameters with the
  request. These are transformed into a format that clj-http can use to
  make multipart HTTP requests. More information on clj-http's usage can
  be found in its README:
  https://github.com/dakrone/clj-http#usage. Your VirusTotal API key
  will be added to this map" {:added "2.0"}
  [path & {:as params}]
  (api-post-generic path (make-multipart-map params)))

(defn api-get
  "Make a HTTP GET request to VirusTotal's API

Arguments:

- path: the relative path of the URL to request

- query-params: keys and values to send as query parameters with the
  request"
  {:added "2.0"}
  [path & {:as query-params}]
  (parse-and-replace-json-body (http/get (url-from-path path)
                                         {:query-params (assoc query-params :apikey VT_API_KEY)})))
