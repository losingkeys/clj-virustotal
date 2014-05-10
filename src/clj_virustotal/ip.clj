(ns clj-virustotal.ip
  "Functions for working with VirusTotal's ip address scanning interface

More information:
https://www.virustotal.com/en/documentation/public-api/#getting-ip-reports"
  (:require [clj-virustotal.core :as vt]))

(defn report
  "Get the report for a given ip

Arguments:

- ip: an ipv4 address in dotted notation"
  {:added "2.0"}
  [ip]
  (vt/api-get "/ip-address/report"
              :ip ip))
