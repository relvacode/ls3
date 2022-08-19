# LS3

Lightweight read-only S3 compatible object storage interface for local filesystems.

- Zero state
- Works across filesystems
- Multiple identities
- Rule based access control

## Authentication and Access Control

Access to LS3 resources are controlled through an identity and an optional global policy.

> An identity that allows access to any action and resource on the server

```json
{
  "Name": "example",
  "AccessKeyId": "EXAMPLE",
  "SecretAccessKey": "<securestring>",
  "Policy": [
    {
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

### Identities

An identity is an access key ID and secret access key pair, along with a policy specific to that identity. An identity
also has a name to identify it in logs, and in conditional policy evaluation.

#### Root Identity

The `root` identity has full access to any action and resource on the server. You can provide an access key id and
secret access key through the
command-line or environment, or ls3 will generate random keys on startup.

#### Public Identity

The `public` identity is a special identity used for when a request provides no authentication mechanism. A public
identity is one that has an empty `AccessKeyId`.

By default, the `public` identity is denied access to everything unless you enable public access.

When public access is not enabled, the public identity is configured as such:

```json
{
  "Name": "public",
  "AccessKeyId": "",
  "Policy": [
    {
      "Deny": true,
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

You can override this behaviour by configuring your own public identity.
When you configure a public identity this overrides the behaviour set by allow public access, and is up to you to deny
access if desired.

### Policies

Policies control what an identity has access to. A policy consists of one or more actions, along with one or more
resources of that action that describe what each policy applies to.

If there are no policies that match a given request then access is denied.

You can configure a global policy that applies to all identities.

#### Wildcards

You can use wildcard characters (`*` and `?`) anywhere in an action or resource. A `*` character matches anything up to
the character proceeding it, and a `?` matches any single character.

> Allow access to s3:GetObject in the `example` bucket on any file that ends with `.txt` or `.html`

```json
{
  "Action": "s3:GetObject",
  "Resource": [
    "example/*.txt",
    "example/*.html"
  ]
}
```

#### Explicit Deny

If a policy is an explicit deny, then any requests that match that policy will be denied. Even if there is another
policy that allows that access.

> Deny any access to the `secret` bucket

```json
{
  "Deny": true,
  "Action": [
    "s3:GetObject",
    "s3:ListBucket"
  ],
  "Resource": "secret/*"
}
```

#### Conditions

You can add one or more `Condition` to any policy that limits the scope of that policy to only requests that match those
conditions.

```json
{
  "Condition": {
    "<ConditionOperator>": {
      "<ContextKey>": [
        "<value>",
        "<value>"
      ]
    }
  }
}
```

> Allow access from 127.0.0.1

```json
{
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "IpAddress": {
      "aws:SourceIp": "127.0.0.1"
    }
  }
}
```

> Deny access if request is not secure (not using HTTPS)

```json
{
  "Deny": true,
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "Bool": {
      "aws:SecureTransport": "false"
    }
  }
}
```

##### Condition Operators

| Operator                    | Description                                                  |
|-----------------------------|--------------------------------------------------------------|
| `StringEquals`              | True if any are exactly equal                                |
| `StringNotEquals`           | True if none are exactly equal                               |
| `StringEqualsIgnoreCase`    | True if any are exactly equal (case insensitive)             |
| `StringNotEqualsIgnoreCase` | True if none are exactly equal (case insensitive)            |
| `StringLike`                | True if matches any wildcard pattern                         |
| `StringNotLike`             | True if not match all wildcard patterns                      |
| `IpAddress`                 | True if matches any IP or CIDR range                         |
| `NotIpAdress`               | True if not matches all IP or CIDR range                     |
| `Bool`                      | True if all boolean values are equal. False if not a boolean |

##### Global Context Keys

These context keys apply to all requests

| Key                   | Type        | Description                                                             |
|-----------------------|-------------|-------------------------------------------------------------------------|
| `aws:SourceIp`        | `IpAddress` | The IP address of the client                                            |
| `aws:SecureTransport` | `Bool`      | Was the request made over HTTPS                                         |
| `aws:username`        | `String`    | The `Name` of the identity making the request. `public` if unauthorized |
| `ls3:authenticated`   | `Bool`      | Is the request made with an authenticated identity                      |