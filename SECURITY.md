# Security policy

CTI Console is a personal learning project, but I take security reports seriously and want to hear about anything you find.

## Supported versions

Only the live version at https://cti-dashboard-tau.vercel.app and the `main` branch of this repository are supported. Fixes are applied there only.

## Reporting a vulnerability

Please report vulnerabilities **privately**, not in a public issue.

1. Go to this repository's **Security** tab
2. Click **Report a vulnerability**
3. Describe the issue, how to reproduce it, and what impact you think it has

I'll aim to acknowledge reports within 7 days and let you know what I plan to do. As a solo project, fix times will vary.

## Scope

**In scope**
- The live site and its API endpoint (`/api/analyze`)
- The code in this repository
- Ways to expose the API keys, bypass the rate limiting, or make the app show a misleading verdict

**Out of scope**
- VirusTotal, AbuseIPDB and Vercel themselves. Report issues with those services to them directly
- Denial of service or load testing. The site runs on free-tier API quotas, so please don't stress test it
- Findings that need physical access to my devices or accounts

## Testing guidelines

- Only test against your own searches. Don't try to affect other visitors
- Keep automated requests to a minimum. Anything that burns through the API quota takes the site down for everyone
- Don't access, change or delete data that isn't yours

## Known limitations

These are documented trade-offs, not vulnerabilities:

- Rate limiting is kept in memory per server instance, so on serverless hosting it's best effort rather than airtight
- Indicators VirusTotal has never seen currently show as Clean rather than "No data"

Thank you for helping keep this project safe.