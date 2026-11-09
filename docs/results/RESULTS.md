# Results vs ground truth insecureshop.yaml (19 items)

| | Model | Recall (average) | Range over runs |
|---|---|---|---|
| Teacher | gemini-3-flash-preview | **78.9%** | 1 run |
| Student before lessons | openai/gpt-oss-120b | **49.1%** | 47%–53% |
| Student after 14 lessons | openai/gpt-oss-120b | **66.7%** | 63%–68% |

**Lift: +17.5 points.** Findings per run 17.7 → 21.3; share matching a known item 53% → 59%.

| # | Item | Teacher | Before | After |
|---|---|---|---|---|
| 1 | Hardcoded Credentials | ✅ | 3/3 | 3/3 |
| 2 | Insufficient URL Validation | ✅ | 1/3 | 0/3 ▼ |
| 3 | Weak Host Validation Check | ❌ | 0/3 | 0/3 |
| 4 | Arbitrary Code Execution | ✅ | 1/3 | 3/3 ▲ |
| 5 | Access to Protected Components | ✅ | 1/3 | 3/3 ▲ |
| 6 | Unprotected Data URIs | ✅ | 3/3 | 3/3 |
| 7 | Theft of Arbitrary | ✅ | 1/3 | 2/3 ▲ |
| 8 | Using Components with Known Vulnerabilities | ❌ | 0/3 | 0/3 |
| 9 | Insecure Broadcast Receiver | ✅ | 0/3 | 1/3 ▲ |
| 10 | AWS Cognito Misconfiguration | ✅ | 3/3 | 3/3 |
| 11 | Insecure use of FilePaths in FileProvider | ✅ | 2/3 | 3/3 ▲ |
| 12 | Use of Implicit intent to send a broadcast with sensitive data | ✅ | 0/3 | 2/3 ▲ |
| 13 | Intercepting Implicit intent to load arbitrary URL | ❌ | 0/3 | 0/3 |
| 14 | Insecure Implementation of SetResult in exported Activity | ❌ | 0/3 | 0/3 |
| 15 | Insecure Content Provider | ✅ | 1/3 | 3/3 ▲ |
| 16 | Lack of SSL Certificate Validation | ✅ | 3/3 | 3/3 |
| 17 | Insecure Webview Properties Enabled | ✅ | 3/3 | 3/3 |
| 18 | Insecure Data Storage | ✅ | 3/3 | 3/3 |
| 19 | Insecure Logging | ✅ | 3/3 | 3/3 |

## How much the lift depends on the match settings

Hits out of 19 per run are in brackets (out of the teacher's findings for the last row).

| Match setting | Teacher | Before lessons | After lessons | Lift (points) |
|---|---|---|---|---|
| Default (anchor within 8 lines of the evidence) | 15/19 | 49.1% (9/10/9) | 66.7% (13/12/13) | **+17.5** |
| Strict (anchor in the quoted evidence only) | 14/19 | 49.1% (9/10/9) | 63.2% (12/12/12) | **+14.0** |
| No anchors (file and type only) | 15/19 | 54.4% (10/11/10) | 66.7% (13/12/13) | **+12.3** |
| Against the teacher's 21 findings instead of the labels | - | 41.3% (8/9/9) | 58.7% (12/12/13) | **+17.5** |

## The 14 lessons the teacher wrote (0 rejected as app-specific)

1. Exported components must not forward an Intent received from an external source to privileged methods like startActivity, startService, or sendBroadcast without strict validation.
2. Loading code from other packages using createPackageContext with CONTEXT_INCLUDE_CODE is dangerous if the package name is not verified via signature comparison.
3. Sensitive data must never be sent via implicit broadcasts because any application on the device can register to intercept the data.
4. WebViews that load URLs from Intent extras or deep link parameters without validation are vulnerable to phishing and local file theft.
5. Exported Content Providers protected by permissions with 'normal' protection level are accessible to any app on the device.
6. Exported or dynamically registered Broadcast Receivers that trigger sensitive UI or logic must validate the incoming Intent data.
7. Using ContentResolver.openInputStream() on a URI provided by an external app can allow that app to trick your application into reading its own private files.
8. Hardcoding backend identifiers, cloud credentials, or API keys in code or resources allows attackers to impersonate the application.
9. Enabling setAllowUniversalAccessFromFileURLs allows JavaScript in a file:// context to bypass the Same-Origin Policy and access any local file or remote origin.
10. Overriding onReceivedSslError and calling handler.proceed() disables all certificate validation, enabling Man-in-the-Middle (MitM) attacks.
11. The <root-path> element in a FileProvider configuration exposes the entire device filesystem to potential URI leakage.
12. Production applications should disable debugging, backups, and cleartext traffic in the manifest to reduce the attack surface.
13. Logging sensitive information like passwords, tokens, or PII to the system log makes it accessible to anyone with physical access or ADB.
14. Storing sensitive data in plaintext in SharedPreferences or local databases is insecure as it can be extracted from backups or rooted devices.

Raw reports, the lessons file and the results JSON are in `docs/results/insecureshop/`.
