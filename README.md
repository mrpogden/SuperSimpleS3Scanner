# Super Simple S3 Scanner
A Lightweight Super Simple S3 Malware scanner. - ALPHA

#Requirements:

1. An API key from VirusTotal.com  *the Free Public key has limits 4 lookups/min 500/day 15k/month*
2. Configured credentials with read access to the bucket you want to scan & (optional, the bucket you want to send quarantined items to).

#How it works:

This is a very lightweight solution to get a basic readout on whether there is anything nasty in your S3 buckets.  It works by simply comparing the hashes of your objects against the database of malicious hashes in VirusTotal.

#Pros.
1. Fast, Serverless, lightweight & much cheaper option that the current marketplace solutions that require EC2 sandboxes to be built.
2. Uses results from 70 different anti-malware engines to determine if the file is malicious or not, so not determined by a single vendor.

#Cons.
1. Like most AV, they are only as good as the signatures in the database. This is no different, Its a hash comparison only, so anything thats not already seen by VT could be missed.  There is no execution or sandbox (hence the lower cost & speed)  But in the grand scheme of Defence in Depth, this would still be a good layer of security.
2. There are some restrictions/limits on the use ofthe VirusTotal API.  Double check these and decide if you need a pro subscription or whether you could use the free version.



 
#To-Do:

This is still very early in the build, but its functional as a concept

1. Tidy up the code.
2. Wrap this up into a Lambda to trigger when new objects are uploaded, then send SNS if anything is found
3. Build in a quarantine mechanism with a more complete report.
4. Create heuristic & on-demand scans
5. Build CloudFormation for easy deployment
 
 
