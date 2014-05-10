(ns clj-virustotal.domain
  "Functions for working with VirusTotal's domain scanning interface

More information:
https://www.virustotal.com/en/documentation/public-api/#getting-domain-reports"
  (:require [clj-virustotal.core :as vt]))

(defn report
  "Get the report for a given domain.

Arguments:

- domain-name: the domain name to retrieve the report for"
  {:added "2.0'"}
  [domain-name]
  (vt/api-get "/domain/report"
              :domain domain-name))
