<!-- notes from session 4 -->
- use zdns for fast dns lookups
- see dot com domain for examples of large scale scans
- check kitterman for spf testing a one that aligns with rfc
- send emails from our own machine using postfix to test dmarc/spf/dkim on different type of domains (very secure ones, medium secure ones, low secure ones)
- try to see if domains has in their spf include other domains that are not registered and see if we can exploit that



SPF POLICY OUTPUTS:
- SoftFail : if the SPF check fails, the mail will still be accepted but marked as suspicious.
- HardFail : if the SPF check fails, the mail will be rejected outright.
- Redirect : This mechanism allows the domain owner to specify that the SPF policy for one domain should be redirected to another domain's SPF policy.
- Neutral : The domain owner is not asserting whether the IP is authorized or not. The mail will be accepted without any special treatment.
- Pass : The IP address is authorized to send mail on behalf of the domain.
- None : No SPF record is published for the domain.


Test script to send email from local machine using sendmail command:

```bash
printf "From: admin@office.com
Subject: Test Email
This is a test email.
Email was sent at $(date)." | sendmail -v -f admin@office.com antonio.mattar@grenoble-inp.org
```