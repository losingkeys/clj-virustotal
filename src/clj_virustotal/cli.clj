(ns clj-virustotal.cli
  "Functions for handling command-line input and making API requests
  based on that input"
  (:require [clj-virustotal.comments :as vt-comments]
            [clj-virustotal.url      :as vt-url]
            [clj-virustotal.domain   :as vt-domain]
            [clj-virustotal.ip       :as vt-ip]
            [clj-virustotal.file     :as vt-file]
            [clojure.tools.cli       :as cli]
            [clojure.string          :as s]))

;; thanks: http://stackoverflow.com/a/11963253/
(defn- in-seq?
  "Returns whether or not `needle` is a member of `coll`"
  {:added "2.0"}
  [coll needle]
  (boolean (some #{needle} coll)))

(def option-descriptions
  "The option descriptions used by clojure.tools.cli to parse command-line
  arguments"
  [["-r" "--resource <resource>[ <resource>]" "" :id :resources]
   ["-e" "--rescan"                           "" :id :rescan]
   ["-s" "--scan <item>[ <item>]"             "" :id :scan]
   ["-h" "--help"                             ""]
   ["-k" "--key"                              ""]])

(def usage
  "A string describing how this command is used"
  "Usage: virustotal <command> [OPTIONS]

These subcommands and generic options are supported:
  comment          Work with comments on VirusTotal's site
  url              Work with URLs
  domain           Work with domains
  ip               Work with ip addresses
  file             Work with files
  -k|--key <key>   Specify your API key via the command line. Takes precedence over the VT_API_KEY environment variable
  -h|--help        Display this help or subcommand help if a subcommand is specified

  Use -h|--help after a subcommand to get specific help for that subcommand")

(defn- help
  "Returns a string describing the options/flags for a given subcommand"
  {:added "2.0"}
  [subcommand]
  (case subcommand
    :comment "Usage: virustotal comment \"Comment here, can contain #tags and @user mentions\""
    :url     "Usage:

  virustotal url -s|--scan <url>                        Queues a scan for the given URL
  virustotal url -r|--resource <resource>[ <resource>]  Gets reports for the given resource(s)

"
    :domain "Usage: virustotal domain <domain>

  Gets a report for the given domain

"
    :ip "Usage virustotal ip <ip>

  Gets a report for the given ipv4 address (needed in dotted notation)"
    :file "Usage:

  virustotal file -s|--scan <filename>[ <filename>]     Queues scans for the given filename(s)
  virustotal file -e|--rescan <resource>[ <resource>]   Queues scans for the given resource(s) that already exist on VirusTotal
  virustotal file -r|--resource <resource>[ <resource>] Gets reports for the given resource(s)"
    nil usage))

(defn- println-err
  "Prints an error to stderr"
  {:added "2.0"}
  [& text]
  (let [*out* *err*]
    (apply println text)))

(defn- get-api-function
  "Given a subcommand and an action, returns the corresponding
  clj-virustotal API function"
  {:added "2.0"}
  [subcommand options]
  (case subcommand
    :comment vt-comments/put
    :url     (if (:scan options)
               vt-url/scan
               vt-url/report)
    :domain  vt-domain/report
    :ip      vt-ip/report
    :file    (cond
              (:scan options)   vt-file/scan
              (:rescan options) vt-file/rescan
              true                      vt-file/report)))

(defn- validate-subcommand-name
  "Returns a symbol indicating the subcommand matching the current
  string. Note: subcommands can be partially specified (so both c and
  comment return :comment)"
  {:added "2.0"}
  [cmd]
  (cond
   (nil? cmd)                                               nil
   (re-find #"^c(?:o(?:m(?:m(?:e(?:n(?:t)?)?)?)?)?)?$" cmd) :comment
   (re-find #"^u(?:r(?:l)?)?$"                         cmd) :url
   (re-find #"^d(?:o(?:m(?:a(?:i(?:n)?)?)?)?)?$"       cmd) :domain
   (re-find #"^ip?$"                                   cmd) :ip
   (re-find #"^f(?:i(?:l(?:e)?)?)?$"                   cmd) :file
   true                                                     nil))

(defn- validate-options-have-resources
  "Checks to see that the given options map has something under
  its :resources key. Prints an error message and exits if no resources
  are found"
  {:added "2.0"}
  [options error-message]
  (when-not (:resources options)
    (println-err error-message)
    (System/exit 1)))

(defn- validate-argument-presence
  "Checks to see that there are more than one arguments. Prints an error
  message and exits if no arguments are found"
  {:added "2.0"}
  [arguments error-message]
  (when (< 1 (count arguments))
    (println-err error-message)
    (System/exit 1)))

(defn- validate-comment-subcommand
  "Validates options/arguments specific to the comment subcommand"
  {:added "2.0"}
  [options arguments]
  (validate-options-have-resources options "Specify which resource to comment on with -r or --resource")
  (validate-argument-presence arguments "Missing comment"))

(defn- validate-url-subcommand
  "Validates options specific to the url subcommand"
  {:added "2.0"}
  [options _]
  ;; rescan and report actions require resources
  (when-not (:scan options)
    (validate-options-have-resources options "Specify which resources you'd like report(s) for with -r or --resource")))

(defn- validate-domain-subcommand
  "Validates arguments specific to the domain subcommand"
  {:added "2.0"}
  [_ arguments]
  (validate-argument-presence arguments "Specify which domain you'd like the report for"))

(defn- validate-ip-subcommand
  "Validates arguments specific to the ip subcommand"
  {:added "2.0"}
  [_ arguments]
  (validate-argument-presence arguments "Specify which ip address you'd like the report for")
  )

(defn- validate-file-subcommand
  "Validates options/arguments specific to the file subcommand"
  {:added "2.0"}
  [options arguments]
  (cond
   (:rescan options) (validate-options-have-resources options "Specify which resource(s) to rescan with -r or --resource")
   (nil? (:scan options)) ;; we're preforming the default action: getting a
                          ;; report
    (validate-options-have-resources options "Specify which resource(s) you'd like report(s) for with -r or --resource")))

(defn parse-and-validate-arguments
  "Parses a list of command-line arguments and exits with a message if
  something is wrong or --help is requested"
  {:added "2.0"}
  [arguments]
  (let [parsed       (cli/parse-opts arguments option-descriptions)
        subcommand   (validate-subcommand-name (get-in parsed [:arguments 0]))
        options      (:options parsed)
        arguments    (rest (:arguments parsed))]

    ;; The user specifically asked for help. Either with a subcommand or in
    ;; general
    (when (:help options)
      (println (help subcommand))
      (System/exit 0))

    ;; The user typed an invalid subcommand (or no subcommand)
    (when-not subcommand
      (println-err usage)
      (System/exit 1))

    (when (:errors parsed)
      (apply println-err (:errors parsed))
      (System/exit 1))

    ;; Ensure we have what we need for the given action (call a function to
    ;; validate the input specifically for this subcommand
    ((case subcommand
       :comment validate-comment-subcommand
       :url     validate-url-subcommand
       :domain  validate-domain-subcommand
       :ip      validate-ip-subcommand
       :file    validate-file-subcommand) options arguments)

    (assoc parsed :subcommand subcommand)))

(defn api-call-from-parsed-arguments
  "Makes an API call and prints the response to stdout"
  {:added "2.0"}
  [parsed]
  (let [subcommand (:subcommand parsed)
        options    (:options parsed)
        ;; the first argument is the subcommand
        arguments  (rest (:arguments parsed))
        api-fn     (get-api-function subcommand options)
        resp       (case subcommand
                     :comment (apply api-fn (:resources options) arguments)
                     :url     (if (:scan options)
                                (api-fn (:scan options))
                                (api-fn (:resources options)))
                     :domain  (api-fn arguments)
                     :ip      (api-fn arguments)
                     :file    (if (:scan options)
                                (api-fn (:scan options))
                                (api-fn (:resources options))))]

    ;; print the response when there's only one item
    (let [message   (get-in resp [:body :verbose-msg])
          code      (get-in resp [:body :response-code])
          permalink (get-in resp [:body :permalink])]
      (if message
        (println message)
        (case code
          -2 (println "Your item is still in the queue")
          0  (println "Item not found")
          1  (println "Item found")
          nil nil))
      (when permalink
        (println "\nPermalink:\n" permalink)))

    ;; print the response when there's more than one item
    (if (sequential? (:body resp))
      (doseq [r (:body resp)]
        (println "Resource: " (:resource r) "\nPermalink:\n" (:permalink r))))))
