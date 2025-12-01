---
title: "B2B Shadow invites: Tracking an upcoming attack vector"
classes: wide
header:
  teaser: /assets/images/projects/Teams/cover1.png
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

# Post-compromise tracking activity

# Mitigations