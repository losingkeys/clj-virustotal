(ns clj-virustotal.comments
  "Functions for working with comments using VirusTotal's API.

More information:
https://www.virustotal.com/en/documentation/public-api/#making-comments"
  (:require [clj-virustotal.core :as vt]))

(defn put
  "Add a comment to a resource.

Arguments:

- resource: an md5/sha1/sha256 hash of the resource to comment on

- comment: the comment to add. This can contain #tags (starting with the
  # symbol, and can mention @users (starting with the # symbol)"
  {:added "2.0"}
  [resource comment]
  (vt/api-post "/comments/put"
               :resource resource
               :comment comment))
