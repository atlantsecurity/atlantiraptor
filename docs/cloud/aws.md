# AWS breach hunting

Atlantiraptor hunts a customer's AWS accounts from the server, alongside the endpoint
hunts. It covers:

- root and console sign-ins, and password spraying
- stolen access keys
- defence evasion: CloudTrail, GuardDuty and Config turned off
- privilege escalation and backdoor roles
- data exposure: public buckets, and snapshots or images shared with other accounts
- cryptomining and LLMjacking
- IAM hygiene

Everything is read-only; nothing in the account is changed.

| | |
|---|---|
| Code | `vql/server/cloud` (`aws_cloudtrail()`, `aws_iam()`, `aws_regions()`) |
| Artifacts | `artifacts/definitions/Cloud/AWS/` |
| Credential | secret type **AWS Creds** (`access_key_id`, `secret_access_key`, optional `session_token`, `role_arn`, `external_id`, `regions`) |
| Tests | `go test ./vql/server/cloud/` runs every hunt against a fake AWS that checks the region and service of each SigV4 signature, using the CloudTrail events and IAM answers in `vql/server/cloud/fixtures/aws` |

## What it finds

Every hunt returns the same columns as the other cloud hunts, `Time, Severity,
Detection, User, IPAddress, Location, Device, Details`.

| Artifact | Finds |
|---|---|
| `Cloud.AWS.ConsoleLogins` | root console sign-ins (critical without MFA), IAM users signing in without MFA, password spraying against many users, brute force, and a successful sign-in from a guessing address |
| `Cloud.AWS.RootActivity` | anything the root user did, grouped by action, address and region |
| `Cloud.AWS.AccessKeyAbuse` | `GetCallerIdentity` calls (how leaked keys are tested), attack tools in the user agent (Pacu, TruffleHog, Kali and others), and long-term keys used from an address not seen in the baseline |
| `Cloud.AWS.SuspiciousChanges` | logging and detection turned off, new access keys and console passwords, admin policies attached, role trust policies changed, public buckets, shared snapshots and images, instances launched (and launched in a region the account does not otherwise use), Bedrock model access (LLMjacking), and destructive actions |
| `Cloud.AWS.IAMPosture` | from the credential report: root access keys, root without MFA, console users without MFA, and stale or never-rotated access keys |
| `Cloud.AWS.Persistence` | roles that anyone or another AWS account can assume, and SAML and OpenID Connect identity providers |
| `Cloud.AWS.CompromiseAssessment` | all of the above in one collection |
| `Cloud.AWS.Monitor` | server event: collects CloudTrail management events from every region continuously and raises alerts |

Shared single-event rules live in `Cloud.AWS.Rules` and are used both by the hunts and
by the monitor. `TrustedAccounts` (a regex of account IDs) in `Persistence` and
`CompromiseAssessment` silences roles that trust the customer's own other accounts.

CloudTrail event history keeps 90 days of management events, per region, without any
trail configured. Start `Cloud.AWS.Monitor` for each customer on day one to keep them
longer. Data events (S3 object reads, Lambda invocations) only exist in a trail and are
not read.

## Setting up access

AWS has two ways in. A cross-account role is the recommended one: the customer creates
no long-term keys, and can cut access off at any time by deleting the role.

### Cross-account role (recommended)

Atlant runs one IAM user in its own AWS account, with a policy that allows only
`sts:AssumeRole`. Its access key is the one credential Atlant holds.

Per customer:

1. Atlant picks an external ID for the customer, a random string such as the output of
   `openssl rand -hex 16`, and sends it with the Atlant AWS account ID.
2. In the customer account, an administrator opens **IAM > Roles > Create role >
   AWS account > Another AWS account**, and enters the Atlant account ID. They tick
   **Require external ID** and paste the external ID.
3. Attach the AWS managed policy **SecurityAudit** and name the role
   `AtlantiraptorAudit`. SecurityAudit is read-only and covers everything the hunts read:
   `cloudtrail:LookupEvents`, `iam:List*`, `iam:GenerateCredentialReport`,
   `iam:GetCredentialReport` and `ec2:DescribeRegions`.
4. The administrator sends back the role ARN
   (`arn:aws:iam::<customer account>:role/AtlantiraptorAudit`).
5. In Atlantiraptor, open **Secrets > AWS Creds > Add**. Name the secret after the customer
   and fill it in:
   - `access_key_id` and `secret_access_key`: the key of the Atlant IAM user
   - `role_arn`: the ARN from step 4
   - `external_id`: the external ID from step 1

   Grant the secret to the users who run the hunts, and to the user who configures
   `Cloud.AWS.Monitor`.
6. Run `Cloud.AWS.CompromiseAssessment` with `AWSSecret` set to the name of the secret,
   and add `Cloud.AWS.Monitor` under Server Events.

The server assumes the role for an hour at a time, as session `atlantiraptor`, so the
customer's own CloudTrail shows every call Atlant made. The external ID stops another
AWS customer who learns the role ARN from using Atlant to reach it.

The trust policy that step 2 creates looks like this:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::<Atlant account>:root"},
    "Action": "sts:AssumeRole",
    "Condition": {"StringEquals": {"sts:ExternalId": "<external ID>"}}
  }]
}
```

### Access key in the customer account

When the customer cannot create a cross-account role, they create an IAM user with only
**SecurityAudit** attached, and an access key for it. Put that key in the secret and
leave `role_arn` and `external_id` empty. Ask the customer to rotate the key
periodically; `Cloud.AWS.IAMPosture` will itself flag it after 365 days.

### Regions

CloudTrail event history is per region, and attackers like regions nobody watches. With
`regions` empty, the hunts read every region enabled for the account
(`ec2:DescribeRegions`). Set `regions` (for example `us-east-1, eu-west-1`) only to
limit them. Sign-ins and IAM changes are global and are logged in `us-east-1`, which is
always worth including. GovCloud regions (`us-gov-west-1`, `us-gov-east-1`) are
supported; China regions are not.

Requests are only ever signed for, and sent to, `amazonaws.com` endpoints built from a
validated region name. A query cannot redirect a customer's credentials elsewhere.

### Errors

| Error | Meaning |
|---|---|
| `AccessDenied` on `AssumeRole` | the trust policy of the role does not name the Atlant account, or the external ID differs |
| `AccessDenied` or `UnauthorizedOperation` on another call | the role lacks SecurityAudit |
| `InvalidClientTokenId`, `SignatureDoesNotMatch` | the Atlant access key (or the customer key) is wrong or deactivated |
| `UnrecognizedClientException`, `OptInRequired` | a region in `regions` is not enabled for the account |

## VQL

```
SELECT * FROM aws_cloudtrail(secret="example", region="us-east-1",
    event_name="ConsoleLogin", start=now() - 86400)

SELECT * FROM foreach(row={ SELECT Region FROM aws_regions(secret="example") },
    query={ SELECT * FROM aws_cloudtrail(secret="example", region=Region,
                                         read_only="false") })

SELECT * FROM aws_iam(secret="example", action="ListRoles")
SELECT * FROM aws_iam(secret="example", action="GetCredentialReport")
```

`aws_cloudtrail()` returns one row per event with `Time, Region, EventSource, EventName,
User, UserType, UserArn, AccountId, AccessKeyId, SourceIP, UserAgent, ErrorCode,
ErrorMessage, ReadOnly, MFA, Request, Response, Additional, Identity, Resources,
EventId`. `User` is `root`, the IAM user name, or `Role/Session` for an assumed role.
LookupEvents takes one filter at a time: `event_name`, `event_source`, `username`,
`access_key` or `read_only`. With `follow=TRUE` it keeps polling with a 30 minute
overlap, because CloudTrail delivers events up to 15 minutes late, and drops repeats by
`EventId`.

`aws_iam()` only calls an allowlist of read-only `List` and `Get` actions and the credential report. It
follows `Marker` paging, returns the list items of the answer as rows, and decodes policy
documents into dictionaries. All three plugins back off and retry when AWS throttles.
