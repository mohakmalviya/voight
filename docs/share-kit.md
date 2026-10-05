# Share Human Gate without publishing the repository

## The demo

`npm run showcase` generates `dist/human-gate-demo.html`: a single file with embedded styles, scripts and measured reports. Open it in a browser or send it to an evaluator. It needs no server, external fonts, analytics, credentials or repository access. Research links open only when clicked. The demonstration shows recorded evidence; it is not a live protection service.

To regenerate evidence, run both benchmarks first and save their JSON reports in `docs/`. To record the demo and check desktop/mobile behavior:

```sh
npm run showcase
node scripts/check-showcase.mjs
```

The recording and screenshots go to `dist/showcase-artifacts`. Use the `.webm` walkthrough for audiences whose chat/email service cannot preview HTML files. The source repository stays private. No hosting service, public repository, outreach message or release is created by these commands.

## Short introduction

I'm building Human Gate, a self-hosted gateway for websites that want more control over automated access. It combines invitation-based passkeys, optional checks for declared browser automation, and download limits that follow a credential across sessions. The demo shows reproducible tests and an important limitation: an approved automated browser can hide its signals and get through, while extraction limits still constrain it. I'm looking for a few technical evaluators to try the passkey flow, test their own browser workflows, and identify compatibility or accessibility problems before a public release.

## Ninety-second walkthrough

1. **0–20 seconds:** Show the three layers: admission, automation declarations, extraction limits. Explain that the content origin remains private.
2. **20–40 seconds:** Select declared browser and WebDriver tests. Point out the zero origin requests in enforcement mode.
3. **40–55 seconds:** Select observe mode. Explain why operators need a compatibility evaluation before rejecting visitors.
4. **55–75 seconds:** Select hidden declarations. Show the admitted automation case openly, then the extraction boundary that still applies.
5. **75–90 seconds:** Open extraction results and download the evidence JSON. Ask evaluators for reproduction steps, environment details and false-rejection reports.

## Pilot feedback template

- Browser/OS and passkey type (no private keys, invitation codes or cookies).
- Intended task and policy mode.
- Expected result and actual result.
- Whether the task involved assistive software or automation, if the evaluator chooses to share that detail.
- Request reference and reproducible steps on synthetic content.

No claim of human-only access, universal agent detection, production readiness or measured human accuracy should accompany this demo. Do not publish private user logs or real website content in demonstration reports.
