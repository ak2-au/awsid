This is the source code for [awsid.dev.ak2.au](https://awsid.dev.ak2.au). The 
interesting files are likely [`template.yml`](/template.yml) and [`web.go`](/web/web.go).

## Caveat regarding logging

If you use this service (rather than deploying it yourself), I can technically
see the values that you enter. I've got some logging (look in web.go) to make things
easier for myself, but even if that code didn't exist, the values would still
be logged to my CloudTrail via `s3:PutAccessPointPolicy` API calls. I'll probably
revisit the logs in a year and write a tweet about the number of times this service
has been used, the number of unique account IDs and principal ARNs I've seen, the
number of countries that people have used it from, stuff like that. I trust me,
but you might not.
