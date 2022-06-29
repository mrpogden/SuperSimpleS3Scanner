# SuperSimpleS3Scanner
A Lightweight Super Simple S3 Malware scanner. - ALPHA

Requirements.  

An API key from VirusTotal.com 
  * the Free Public key has limits 4 lookups/min 500/day 15k/month

Configured credentials with read access to the bucket you want to scan.

How it works,
 This is a very lightweight solution to get a basic nod on whether there is anything nasty in your S3 buckets.  It works by simply comparing the hashes of your objects against the database of malicious hashes in VirusTotal.
 
 
 To-Do:
  *Tidy up the code.
  *Wrap this up into a Lambda to trigger when new objects are uploaded, then send SNS if anything is found
 
 
