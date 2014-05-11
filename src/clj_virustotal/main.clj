(ns clj-virustotal.main
  "Holds the main interface to the command-line interface provided by
  clj-virustotal.cli"
  (:require [clj-virustotal.cli :as vt-cli])
  (:gen-class))

(defn -main
  "The main entry-point for the command-line interface provided by
  clj-virustotal.cli"
  {:added "2.0"}
  [& args]
  (vt-cli/api-call-from-parsed-arguments (vt-cli/parse-and-validate-arguments args)))
