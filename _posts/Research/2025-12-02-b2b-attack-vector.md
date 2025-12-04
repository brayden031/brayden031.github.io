---
title: "B2B Guest access: Tracking an upcoming attack vector"
classes: wide
header:
  teaser: /assets/images/projects/Teams/cover1.jpg
ribbon: MidnightBlue
description: "A technical deep dive into how B2B guest invites in Microsoft Teams can be detected, traced, and contained before they evolve into a full attack vector."
categories:
  - Research
toc: true
---

# Introduction

Research has emerged highlighting a critical security gap in the architectural setup of Microsoft teams cross-tenant collaboration. The vulnerability exists when a user joins as a guest into an external tenant, their protection level will then be controlled entirely be that environment. Therefore, this has introduced a new attack vector that allows a threat actor to build a malicious tenant that turns off all security features such as:

1. Safe links - Protects organizations from malicious links that are used in phishing and other attacks.
2. ZAP - Retroactively detects and neutralizes malicious phishing, spam, or malware messages.
3. Real-time URL scanning - Pre-emptive malicious domain blocking.
4. Safe attachments - Virtual environment to check attachments.

Essentially, allowing a threat actor to exploit a blind spot within organisations security monitoring.

This blog is based off the initial news article produced by 'Bleeping Computer' followed by the blog post put out by 'ontinue' that details the specifics of this attack vector.

This research runs in parallel but with it differing by specifically looking at detection logic, post-compromise tracking activity, and overall mitigations.

# KQL detection logic

These detections leverage KQL (Kusto-Query-Language) to identify phases 3 & 4 as identified in the ontinue blog to look for users receiving invites to external tenants.

The first detection is a simplified search that looks for successfull teams sign ins to external guest tenants. Even though this is effective, it doesn't fully track the entire attack chain so has a lower true positive confidence than the second query.

```
let trusted_tenants = dynamic([]);
SigninLogs
| where AppDisplayName has "Microsoft Teams" and ResultType == 0
| where UserType == "Member" and CrossTenantAccessType == "b2bCollaboration"
| where ResourceTenantId !in (trusted_tenants)
| where isnotempty(ResourceTenantId) and isnotempty(HomeTenantId) and ResourceTenantId != HomeTenantId
| project TimeGenerated, IPAddress, Location, UserPrincipalName, UserDisplayName,  ExternalTenantID = ResourceTenantId, ExternalTenantName = ResourceDisplayName
```

This second query aims to track the wider process by mapping out the invite event followed by successfull sign ins to an external tenant. Providing a much likely indicator of compromise.

```
let lookbackDays = 7d;
let trusted_tenants = dynamic([]); // FP expected external tenants
// -- Email invite lures --
let TeamsInviteEmails = EmailEvents
| where TimeGenerated >= ago(lookbackDays)
| where SenderFromAddress has_cs "teams.microsoft.com" // Region variants exist so looks to match domain instead
| where Subject has_cs "sent you a message" or Subject has_cs "has sent you a message"
| project InviteTime, InviteSource = "Email", InviteRecipient = RecipientEmailAddress, InviteActor = SenderFromAddress, InviteSubject = Subject, RecipientDomain;
// -- Successful sign-ins to external tenants by filtering out any known internal tenants and FP expected ones -- 
let Signins = SigninLogs
| where TimeGenerated >= ago(lookbackDays)
| where AppDisplayName has "Microsoft Teams" and ResultType == 0
| where UserType == "Member" and CrossTenantAccessType == "b2bCollaboration"
| where ResourceTenantId !in (trusted_tenants)
| where isnotempty(ResourceTenantId) and isnotempty(HomeTenantId) and ResourceTenantId != HomeTenantId
| project SigninTime = TimeGenerated, IPAddress, Location, UserPrincipalName, UserDisplayName, ExternalTenantID = ResourceTenantId, ExternalTenantName = ResourceDisplayName;
// -- Correlate invite -> sign in to external tenant -- 
TeamsInviteEmails
| join kind=inner (
    Signins
) on $left.InviteRecipient == $right.UserPrincipalName
| where SigninTime >= InviteTime
| project InviteTime, SigninTime, InviteRecipient, RecipientDomain, InviteSource, InviteActor, InviteSubject, ExternalTenantID, ExternalTenantName, IPAddress, Location
```

This query is still being refined as yet to see an in the wild case to verify this accurately triggers. However, I have used LLM sample data against these queries which have proven successful in both true positive and false positive events. 

Note: I did also try to include the teams message activity for this attack vector however this proved difficult given the appropriate tables (OfficeActivity & CloudAppEvents) don't pull enough relevant data (sender & recipient) for tracking this.

# Post-compromise tracking activity

Following the detections if it has been determined the victim user accepted the invitation, then the following methods can be used to map the tenant ID to the tenant company name.

PowerShell module to get a company display name and the default domain of a tenant by Id:
https://www.powershellgallery.com/packages/MSIdentityTools/2.0.70
 
Alternatively, this information can be found by querying the Microsoft graph API with the following line:
 
Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/tenantRelationships/findTenantInformationByTenantId(tenantId='x')"

This is necessary in identifying whether the external tenant is expected within the environment. If not, from here additional OSINT will be required to see whether this is part of a known threat actors campaign. Alongside this initiating a thorough endpoint/user account investigation for the involved entities.

# Mitigations

This new attack vector can be protected against using the following strategies:

1. Restrict B2B collaboration in ENTRA settings 
2. Implement Cross-Tenant Access Policies 
3. Restrict External Teams Communication 
4. Applying above detection logic
5. User training against this new attack vector

# Conclusion

This new feature has already been released in a targeted format throughout November and is expected to be fully released in January 2026. Therefore, it's critical to ensure the above mitigations are in place before threat actors have the ability to start adopting this into their TTPs.

# Sources

https://thehackernews.com/2025/11/ms-teams-guest-access-can-remove.html
https://www.ontinue.com/resource/blog-microsoft-chat-with-anyone-understanding-phishing-risk/
https://learn.microsoft.com/en-us/entra/external-id/allow-deny-list
https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview
https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-meetings-chat?tabs=organization-settings