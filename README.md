# Active Scan +++
More scan checks because Burp's scanner is good, but I want more. 

To use simply install the extention and run an active scan. 

The CORS check will take the domain from a valid origin header and use that as a "trusted" domain to test bypasses on. Therefore it is worth running the scan against different requests with different Origin header values.

## Ideas
- Should be able to provide a list of in-scope domains / possibly trusted domains
- From this list, run subdomain enumeration on each domain
- From that final list, check for CORS implementations i.e. "Trusted Domains"
- From THAT list, try to bypass each trusted domain to find exploits for permissive cors

## TO-DO
- [x] Trigger simple cors check to find trusted domains based off of subdomain list + user input
- [x] Using list of then trusted domains, we need to run the cors scan against them....
- [ ] Implement global settings that will allow disabling the trusted domains lookup - given that it can leak parent domain to third-party service