(defproject clj-virustotal "0.1.0-SNAPSHOT"
  :description "An API wrapper for VirusTotal. More info:
https://www.virustotal.com/en/documentation/public-api/"
  :url "https://losingkeys.github.io/clj-virustotal"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.5.0-alpha3"]
                 [cheshire "5.3.1"]
                 [clj-http "0.9.1"]
                 [digest "1.4.4"]
                 [org.clojure/tools.cli "0.3.1"]]
  :plugins [[codox "0.8.0"]]
  ;; thanks: https://github.com/technomancy/leiningen/blob/stable/doc/TUTORIAL.md#uberjar
  :main clj-virustotal.main
  :aot [clj-virustotal.main])
