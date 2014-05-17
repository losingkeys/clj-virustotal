(ns clj-virustotal.url
  "Functions for working with VirusTotal's url scanning interface

More information:
https://www.virustotal.com/en/documentation/public-api/#scanning-urls"
  (:require [clj-virustotal.core :as vt]
            [clojure.string :as s]))

(defn scan
  "Submit a URL to be scanned. When the scan is finished, you can use
  the 'report' function from this namespace to get the report for the
  scanned URL.

Arguments:

- url: the url to scan"
  {:added "1.0.0"}
  [url]
  (vt/api-post "/url/scan"
               :url url))

(defn report
  "Get the report for a scanned URL

Arguments:

- resource: the resources you want the scan report for (normally limited
  to 4 per request). This can also be a 'scan id', which is in the
  format \"sha356-timestamp\". These are usually returned from API calls
  that scan things or get information about resources.

- scan: (optional) - 1 if VirusTotal will scan this URL when no report
  is found. Default is 0."
  {:added "1.0.0"}
  [& resources]
  (let [all-but-last (take (dec (count resources)) resources)
        possible-scan-option (last resources)]
    ;; assume the last argument is the "scan" option if it's an integer or a 1
    ;; character string
    (if (or (integer? possible-scan-option)
            (= 1 (count possible-scan-option)))
      (vt/api-post "/url/report"
                   :resource (s/join "," all-but-last)
                   :scan (str possible-scan-option))
      (vt/api-post "/url/report"
                   :resource (s/join "," resources)))))
