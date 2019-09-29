# cloudfront-sg-manager

A Lambda function for updating the **cloudfront** EC2 security group ingress rules
with the CloudFront IP range changes.

## Deploy the Lambda

This Lambda uses AWS Serverless Application Model Command Line Interface (SAM CLI) as a method of deployment. To start off, set yourself up with a Python 3.7 Virtual Environment and then run the following:

```bash
pip install -r requirements.txt
```

Deployment templates and the function itself can then be found in the **sam-cloudfront-sg-manager** directory.

## Acknowledgements

This Project is an evolution of the [Update Security Groups Lambda](https://github.com/aws-samples/aws-cloudfront-samples/tree/master/update_security_groups_lambda) provided by AWS. I've taken that work as both inspiration and methodology, updating for Python 3.6+ and integrating AWS SAM as a deployment method.
