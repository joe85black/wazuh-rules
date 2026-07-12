# AWS

Rules for Wazuh's native [AWS integration](https://documentation.wazuh.com/current/cloud-security/amazon/index.html), focused on CloudWatch and WAF events.

| File | Purpose |
|---|---|
| `100030-amazon_aws_cloudwatch.xml` | Rules (group `amazon,aws,cloudwatch`) covering AWS WAF actions by rule type and general CloudWatch-delivered events — rule IDs 100030+ |

**Prerequisite:** the `aws-s3` wodle configured on the manager (`ossec.conf`) pulling the relevant CloudWatch/WAF logs from S3.
