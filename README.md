# public
general public repo

## aws
### start-and-update-dns.py
Start and instance and update a dns record with the instances public ip.

### start-and-update-dns.py
> start-and-update-dns.py -s -v [-n|-nf] -w -i *instance name* -r *dns record* -z *dns hosted zone*  

awscli needs to be installed and configured.  
Requires boto3.  
aws region configured in awscli is used for instances.  
If any of -i, -r or -z are ommitted a list will be displayed.  
-n raise system notifications.  
-nf only raise notification on completion or error.  
-s silent.  
-v output responses from aws.  
-w wait for user to press return before exit.  