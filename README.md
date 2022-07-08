# public
general public repo

## aws
### start-and-update-dns.py
Start and instance and update a dns record with the instances public ip.

### start-and-update-dns.py
awscli needs to be installed and configured.
Requires boto3.
aws region configured in awscli is used for instances.
*start-and-update-dns.py -s -v -i <instance name> -r <dns record> -z <dns hosted zone>*
If any of -i, -r or -z are ommitted a list will be displayed
-v output responses to aws