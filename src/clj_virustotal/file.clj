(ns clj-virustotal.file
  "Functions for working with VirusTotal's url file scanning interface

More information:
https://www.virustotal.com/en/documentation/public-api/#scanning-files"
  (:require [clj-virustotal.core :as vt]
            [clojure.string :as s]
            [clojure.java.io :as io]))

(defn scan
  "Scan one or more files

Arguments:

- file-paths: absolute or relative file paths of files that should be
  uploaded to VirusTotal and scanned. Note: each file will be uploaded
  with its original filename"
  {:added "1.0.0"}
  [& file-paths]
  (vt/api-post-generic "/file/scan"
                       {:multipart (map #(let [f (io/file %)]
                                           {:name (.getName f)
                                            :part-name "file"
                                            :content f})
                                        file-paths)}))

(defn rescan
  "Rescan files VirusTotal already has on its servers

Arguments:

- resources: a list of md5/sha1/sha256 hashes of files to be
  re-scanned. By default 25 are allowed per request"
  {:added "1.0.0"}
  [& resources]
  (vt/api-post "/file/rescan"
               :resource (s/join "," resources)))

(defn report
  "Get scan reports for files

Arguments:

- resources: a list of md5/sha1/sha256 hashes of files to get reports
  for. These can also be 'scan ids' in the format
  \"sha256-timestamp\". By default 4 are allowed per request"
  {:added "1.0.0"}
  [& resources]
  (vt/api-post "/file/report"
               :resource (s/join "," resources)))
