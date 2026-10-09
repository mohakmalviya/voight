# Automation declarations

`AUTOMATION_POLICY=observe` is the default. This is a narrow declaration policy, not a trained human/bot classifier.

| Mode | Behavior |
| --- | --- |
| `off` | Ignore declarations, do not persist browser reports, leave admission and extraction controls active |
| `observe` | Record named signals and the ceremony's boolean WebDriver report without rejecting it |
| `enforce` | Reject positive declarations; require a boolean browser report during enrollment/login; require older sessions with missing reports to authenticate again |

The gateway recognizes the standalone user-agent tokens `HeadlessChrome`, `Playwright`, `Puppeteer`, and `Selenium`. The gate page sends one boolean: whether `navigator.webdriver === true`. No mouse, typing, canvas, font, screen, hardware, IP-reputation or cross-site behavioral fingerprint is collected.

The server associates the report with a single-use ceremony, then stores it with the verified session. A submitted verification payload cannot replace the ceremony report. The user-agent declaration is checked on protected requests; the stored browser declaration is rechecked when the session is admitted. Logout, revocation and expired-session pruning cascade to the stored report. Gate assets and logout remain accessible so rejected visitors can read help and end sessions. No declaration can grant access without normal passkey verification.

Audit logs contain only constant signal names (`webdriver`, `declared_user_agent`), never the raw user agent or browser report payload. `observe` may record signals on multiple requests. Counts of log entries are not counts of unique people or bots.

## Limitations and rollout

A script can lie about its report or suppress both declarations. A browser extension or agent taking over a previously approved browser may not change them. Our browser benchmark explicitly demonstrates successful automation with suppressed signals, an invitation, and a virtual passkey. The extraction limits still bound that session.

Automation can also be used for legitimate testing or assistive workflows. Run observe mode with consenting pilot users first; inspect rejections and accessibility issues before enabling enforcement. There is no measured human false-rejection rate yet. A negative signal is not a human label, and observe mode is not a guarantee that enforcement will be compatible with your users.

Enforcement improves handling of clients that declare automation. It cannot deliver complete exclusion of agents from approved browsers. See [research and priorities](research.md) and [browser evaluation](browser-benchmark.md).
