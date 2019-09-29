# cloudfront-sg-manager

A Lambda function for updating the **cloudfront** EC2 security group ingress rules
with the CloudFront IP range changes.

## Deploy the Lambda

The Serverless Application Model Command Line Interface (SAM CLI) is an extension of the AWS CLI that adds functionality for building and testing Lambda applications. It uses Docker to run your functions in an Amazon Linux environment that matches Lambda. It can also emulate your application's build environment and API.

To use the SAM CLI, you need the following tools.

* AWS CLI - [Install the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html) and [configure it with your AWS credentials].
* SAM CLI - [Install the SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html)
* Node.js - [Install Node.js 10](https://nodejs.org/en/), including the NPM package management tool.
* Docker - [Install Docker community edition](https://hub.docker.com/search/?type=edition&offering=community)

The SAM CLI uses an Amazon S3 bucket to store your application's deployment artefacts. If you don't have a bucket suitable for this purpose, create one. Replace `BUCKET_NAME` and `PROFILE` in the commands in this section with a unique bucket name and account alias as appropriate for your environment.

To prepare the application for deployment, use the `sam package` command.

```bash
sam package --output-template-file packaged.yaml --s3-bucket BUCKET_NAME --profile PROFILE
```

The SAM CLI creates deployment packages, uploads them to the S3 bucket, and creates a new version of the template that refers to the artefacts in the bucket.

Then Publish the application:

```bash
sam publish --template-file packaged.yaml --profile PROFILE
```

To deploy the application, use the `sam deploy` command.

```bash
sam deploy --template-file packaged.yaml --stack-name cloudfront-sg-manager --profile PROFILE
```

## Security Group

This Lambda function updates a total possibility of 4 EC2 security groups tagged as the following:
*  `Name: cloudfront_global` and `AutoUpdate: true` and a `Protocol` tag with value `http` or `https`.
*  `Name: cloudfront_region` and `AutoUpdate: true` and a `Protocol` tag with value `http` or `https`.

**Note:** For CloudFront to properly connect to your origin over HTTP or HTTPS only, you will need two security groups with `Name: cloudfront_global` and `Name: cloudfront_region` set for http or https depending on the protocol used. If you require both HTTP and HTTPS protocols to your origin, you will need a total of 4 security groups.

In the cloudformation-resources/shared/infrastructure folder, there is a CloudFormation Template providing two security groups configured to receive HTTPS updates from this Lambda.

## Event Source

This lambda function is designed to be subscribed to the
[AmazonIpSpaceChanged](http://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html#subscribe-notifications)
SNS topic. In the _Add Event Source_ dialog, select **SNS** in the *Event source type*, and populate *SNS Topic* with `arn:aws:sns:us-east-1:806199016981:AmazonIpSpaceChanged`.


## Test Lambda Function
Now that you have created your function, it’s time to test it and initialise your security group(s):

1.  In the Lambda console on the Functions page, choose your function, choose the Actions drop-down menu, and then Configure test event.
2.  Enter the following as your sample event, which will represent an SNS notification.

```
{
  "Records": [
    {
      "EventVersion": "1.0",
      "EventSubscriptionArn": "arn:aws:sns:EXAMPLE",
      "EventSource": "aws:sns",
      "Sns": {
        "SignatureVersion": "1",
        "Timestamp": "1970-01-01T00:00:00.000Z",
        "Signature": "EXAMPLE",
        "SigningCertUrl": "EXAMPLE",
        "MessageId": "95df01b4-ee98-5cb9-9903-4c221d41eb5e",
        "Message": "{\"create-time\": \"yyyy-mm-ddThh:mm:ss+00:00\", \"synctoken\": \"0123456789\", \"md5\": \"2e967e943cf98ae998efeec05d4f351c\", \"url\": \"https://ip-ranges.amazonaws.com/ip-ranges.json\"}",
        "Type": "Notification",
        "UnsubscribeUrl": "EXAMPLE",
        "TopicArn": "arn:aws:sns:EXAMPLE",
        "Subject": "TestInvoke"
      }
    }
  ]
}
```
3.  After you’ve added the test event, click Save and test. Your Lambda function will be invoked, and you will see log output at the bottom of the console similar to the following.
<pre>
Updating from https://ip-ranges.amazonaws.com/ip-ranges.json
MD5 Mismatch: got <b>be3b58ff13ee695c65e0a3eefe7f0218</b> expected 2e967e943cf98ae998efeec05d4f351c: Exception
Traceback (most recent call last):
  File "/var/task/lambda_function.py", line 29, in lambda_handler
    ip_ranges = json.loads(get_ip_groups_json(message['url'], message['md5']))
  File "/var/task/lambda_function.py", line 50, in get_ip_groups_json
    raise Exception('MD5 Missmatch: got ' + hash + ' expected ' + expected_hash)
Exception: MD5 Mismatch: got <b>be3b58ff13ee695c65e0a3eefe7f0218</b> expected 2e967e943cf98ae998efeec05d4f351c
</pre>
You will see a message indicating there was a hash mismatch. Normally, a real SNS notification from the IP Ranges SNS topic will include the right hash, but because our sample event is a test case representing the event, you will need to update the sample event manually to have the expected hash.

4.  Edit the sample event again, and this time change the md5 hash **that is bold** to be the first hash provided in the log output. In this example, we would update the sample event with the hash “be3b58ff13ee695c65e0a3eefe7f0218”.


5.  Click Save and test, and your Lambda function will be invoked.

This time, you should see output indicating your security group was properly updated. If you go back to the EC2 console and view the security group you created, you will now see all the CloudFront IP ranges added as allowed points of ingress. If your log output is different, it should help you identify the issue.

## Resources

See the [AWS SAM developer guide](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/what-is-sam.html) for an introduction to SAM specification, the SAM CLI, and serverless application concepts.

## Acknowledgements

This Project is an evolution of the [Update Security Groups Lambda](https://github.com/aws-samples/aws-cloudfront-samples/tree/master/update_security_groups_lambda) provided by AWS. I have taken that work as both inspiration and methodology, updating for Python 3.6+ and integrating AWS SAM as a deployment method.
