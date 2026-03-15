---
name: implementing-api-threat-protection-with-apigee
description: Implement API threat protection using Google Apigee policies including JSON/XML threat protection, OAuth 2.0, SpikeArrest, and Advanced API Security for OWASP Top 10 defense.
domain: cybersecurity
subdomain: api-security
tags: [apigee, api-gateway, threat-protection, json-threat-protection, xml-threat-protection, spike-arrest, oauth2, google-cloud, owasp-api-top-10]
version: "1.0"
author: mahipal
license: Apache-2.0
---

# Implementing API Threat Protection with Apigee

## Overview

Google Apigee is an enterprise API management platform that provides native security policies for threat protection, including JSON and XML content validation, OAuth 2.0 enforcement, SpikeArrest rate limiting, regular expression threat protection, and Advanced API Security for detecting malicious clients and API abuse patterns. Apigee operates as a reverse proxy that intercepts all API traffic, applying security policies before requests reach backend services, effectively shielding APIs against the OWASP API Security Top 10 threats.

## Prerequisites

- Google Cloud Platform account with Apigee organization provisioned
- Apigee X or Apigee hybrid environment configured
- Backend API services deployed and accessible from Apigee
- Google Cloud CLI (gcloud) installed and authenticated
- OpenAPI specification for target APIs
- Understanding of Apigee proxy bundle structure

## Core Security Policies

### 1. JSON Threat Protection

Protects against JSON-based denial-of-service attacks by limiting structural depth, entry counts, and string lengths:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<JSONThreatProtection name="JSON-Threat-Protection-1">
    <DisplayName>JSON Threat Protection</DisplayName>
    <Source>request</Source>
    <!-- Maximum nesting depth of JSON structure -->
    <ObjectEntryNameLength>50</ObjectEntryNameLength>
    <ObjectEntryCount>25</ObjectEntryCount>
    <ArrayElementCount>100</ArrayElementCount>
    <ContainerDepth>5</ContainerDepth>
    <StringValueLength>500</StringValueLength>
</JSONThreatProtection>
```

### 2. XML Threat Protection

Shields against XML bombs, XXE attacks, and oversized XML payloads:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<XMLThreatProtection name="XML-Threat-Protection-1">
    <DisplayName>XML Threat Protection</DisplayName>
    <Source>request</Source>
    <NameLimits>
        <Element>50</Element>
        <Attribute>50</Attribute>
        <NamespacePrefix>20</NamespacePrefix>
        <ProcessingInstructionTarget>50</ProcessingInstructionTarget>
    </NameLimits>
    <ValueLimits>
        <Text>1000</Text>
        <Attribute>500</Attribute>
        <NamespaceURI>256</NamespaceURI>
        <Comment>256</Comment>
        <ProcessingInstructionData>256</ProcessingInstructionData>
    </ValueLimits>
    <StructureLimits>
        <NodeDepth>5</NodeDepth>
        <AttributeCountPerElement>5</AttributeCountPerElement>
        <NamespaceCountPerElement>3</NamespaceCountPerElement>
        <ChildCount>25</ChildCount>
    </StructureLimits>
</XMLThreatProtection>
```

### 3. Regular Expression Threat Protection

Detects SQL injection, XSS, and other injection patterns in request parameters:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<RegularExpressionProtection name="RegEx-Threat-Protection-1">
    <DisplayName>Regex Injection Protection</DisplayName>
    <Source>request</Source>
    <IgnoreUnresolvedVariables>false</IgnoreUnresolvedVariables>

    <!-- SQL Injection patterns -->
    <QueryParam name="*">
        <Pattern>[\s]*((delete)|(exec)|(drop\s*table)|(insert)|(shutdown)|(update)|(\bor\b))</Pattern>
    </QueryParam>

    <!-- XSS patterns -->
    <QueryParam name="*">
        <Pattern>[\s]*&lt;\s*script\b[^&gt;]*&gt;[^&lt;]+&lt;\s*/\s*script\s*&gt;</Pattern>
    </QueryParam>

    <!-- Header injection -->
    <Header name="*">
        <Pattern>[\r\n]</Pattern>
    </Header>

    <!-- URI path traversal -->
    <URIPath>
        <Pattern>(/\.\.)|(\.\./)</Pattern>
    </URIPath>

    <!-- JSON body injection -->
    <JSONPayload>
        <JSONPath>$.*</JSONPath>
        <Pattern>[\s]*((delete)|(exec)|(drop\s*table)|(insert)|(shutdown)|(update))</Pattern>
    </JSONPayload>
</RegularExpressionProtection>
```

### 4. SpikeArrest Policy

Prevents traffic spikes from overwhelming backend services:

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<SpikeArrest name="Spike-Arrest-1">
    <DisplayName>API Spike Arrest</DisplayName>
    <Rate>30ps</Rate> <!-- 30 per second smoothed -->
    <Identifier ref="request.header.x-api-key"/>
    <MessageWeight ref="request.header.x-request-weight"/>
    <UseEffectiveCount>true</UseEffectiveCount>
</SpikeArrest>
```

### 5. OAuth 2.0 Token Validation

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<OAuthV2 name="Verify-OAuth-Token">
    <DisplayName>Verify OAuth 2.0 Access Token</DisplayName>
    <Operation>VerifyAccessToken</Operation>
    <ExternalAuthorization>false</ExternalAuthorization>
    <ExternalAccessToken>request.header.Authorization</ExternalAccessToken>
    <SupportedGrantTypes>
        <GrantType>authorization_code</GrantType>
        <GrantType>client_credentials</GrantType>
    </SupportedGrantTypes>
    <Scope>read write</Scope>
    <GenerateResponse enabled="true"/>
</OAuthV2>
```

### 6. API Key Validation

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<VerifyAPIKey name="Verify-API-Key-1">
    <DisplayName>Verify API Key</DisplayName>
    <APIKey ref="request.header.x-api-key"/>
</VerifyAPIKey>
```

## Proxy Bundle Configuration

### Complete Secure Proxy Flow

```xml
<!-- apiproxy/proxies/default.xml -->
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<ProxyEndpoint name="default">
    <PreFlow name="PreFlow">
        <Request>
            <!-- Step 1: Verify API Key or OAuth token -->
            <Step>
                <Name>Verify-OAuth-Token</Name>
            </Step>
            <!-- Step 2: Rate limiting -->
            <Step>
                <Name>Spike-Arrest-1</Name>
            </Step>
            <!-- Step 3: Threat protection -->
            <Step>
                <Name>JSON-Threat-Protection-1</Name>
                <Condition>request.header.Content-Type = "application/json"</Condition>
            </Step>
            <Step>
                <Name>XML-Threat-Protection-1</Name>
                <Condition>request.header.Content-Type = "text/xml"</Condition>
            </Step>
            <!-- Step 4: Injection prevention -->
            <Step>
                <Name>RegEx-Threat-Protection-1</Name>
            </Step>
            <!-- Step 5: CORS enforcement -->
            <Step>
                <Name>CORS-Policy</Name>
            </Step>
        </Request>
        <Response>
            <!-- Remove internal headers from response -->
            <Step>
                <Name>Remove-Internal-Headers</Name>
            </Step>
            <!-- Add security headers -->
            <Step>
                <Name>Add-Security-Headers</Name>
            </Step>
        </Response>
    </PreFlow>

    <Flows>
        <Flow name="sensitive-operations">
            <Description>Additional protection for sensitive endpoints</Description>
            <Request>
                <Step>
                    <Name>Quota-Strict</Name>
                </Step>
            </Request>
            <Condition>(proxy.pathsuffix MatchesPath "/admin/**") or
                       (proxy.pathsuffix MatchesPath "/users/*/sensitive")</Condition>
        </Flow>
    </Flows>

    <HTTPProxyConnection>
        <BasePath>/v1</BasePath>
        <VirtualHost>secure</VirtualHost>
    </HTTPProxyConnection>

    <RouteRule name="default">
        <TargetEndpoint>default</TargetEndpoint>
    </RouteRule>
</ProxyEndpoint>
```

### Security Headers Policy

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<AssignMessage name="Add-Security-Headers">
    <DisplayName>Add Security Response Headers</DisplayName>
    <Set>
        <Headers>
            <Header name="X-Content-Type-Options">nosniff</Header>
            <Header name="X-Frame-Options">DENY</Header>
            <Header name="Strict-Transport-Security">max-age=31536000; includeSubDomains</Header>
            <Header name="Cache-Control">no-store, no-cache, must-revalidate</Header>
            <Header name="Content-Security-Policy">default-src 'none'</Header>
            <Header name="X-Request-ID">{messageid}</Header>
        </Headers>
    </Set>
    <Remove>
        <Headers>
            <Header name="X-Powered-By"/>
            <Header name="Server"/>
        </Headers>
    </Remove>
    <IgnoreUnresolvedVariables>false</IgnoreUnresolvedVariables>
    <AssignTo createNew="false" transport="http" type="response"/>
</AssignMessage>
```

## Advanced API Security

Enable Apigee's Advanced API Security add-on for machine-learning-based threat detection:

```bash
# Enable Advanced API Security on Apigee X instance
gcloud apigee organizations update $ORG_NAME \
  --advanced-api-security-config=enabled

# View detected abuse alerts
gcloud apigee apis security-reports list \
  --organization=$ORG_NAME \
  --environment=$ENV_NAME

# Create security action to block suspicious traffic
gcloud apigee security-actions create \
  --organization=$ORG_NAME \
  --environment=$ENV_NAME \
  --action-type=DENY \
  --condition-type=IP_ADDRESS \
  --condition-values="192.168.1.100,10.0.0.50" \
  --description="Block identified malicious IPs"
```

## Deployment

```bash
# Deploy proxy bundle with security policies
gcloud apigee apis deploy \
  --api=$API_NAME \
  --environment=$ENV_NAME \
  --revision=$REVISION \
  --organization=$ORG_NAME

# Validate deployment
gcloud apigee apis list-deployments \
  --api=$API_NAME \
  --organization=$ORG_NAME
```

## References

- Apigee JSON Threat Protection: https://cloud.google.com/apigee/docs/api-platform/reference/policies/json-threat-protection-policy
- Google Cloud Apigee Security Best Practices: https://cloud.google.com/architecture/best-practices-securing-applications-and-apis-using-apigee
- Apigee Advanced API Security: https://docs.cloud.google.com/apigee/docs/api-security
- Apigee OWASP API Top 10: https://docs.apigee.com/api-platform/faq/owasp-top-api-threats
- Wallarm Apigee Security Policies Guide: https://lab.wallarm.com/what/apigee-api-security-policies-howto/
