# S3 buckets enumeration with ffuf

There are multiple ways to address the bucket:

* **Virtual Hosted Style Access**:
  * https://s3.Region.amazonaws.com/bucket-name/key
* **Path-Style Access**:
  * https://bucket-name.s3.Region.amazonaws.com/key

```
ffuf -X HEAD \
-u "https://s3.us-east-1.amazonaws.com/DOMAIN"  \
-w "full.txt:DOMAIN" \
-fc 400 -v
```
