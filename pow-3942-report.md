# Threat Intel — pow-3942 eBay QR Phishing
Date: 2026-10-03

## Source
eBay buyer "pow-3942" (account created 2026-10-01, zero feedback) sent a QR code
in eBay Messages claiming it was an order confirmation. No order was ever placed.
Message reported to eBay as scam; buyer blocked 2026-10-03.

## QR Decode
URL embedded in QR: https://ebay.sellerpaymentverifi.com/lk7q02v8

## Domain Analysis
- Real domain: sellerpaymentverifi.com (typosquat — "verifi" not "verify";
  "ebay" used as subdomain for legitimacy)
- Registered: 2026-09-29 (4 days old — fresh burner)
- Registrar: OwnRegistrar, Inc.
- Nameservers: Cloudflare (SULLIVAN.NS.CLOUDFLARE.COM, ZOE.NS.CLOUDFLARE.COM)
  — real hosting IP hidden behind Cloudflare proxy
- Status: active, expires 2027-09-29

## Assessment
Textbook fresh phishing domain: typosquat of eBay seller payment verification,
registered days before use, proxied through Cloudflare. Designed to harvest
eBay seller credentials and/or payment info from QR scanners.

## Actions taken
- [x] Buyer reported to eBay (reason: Scam)
- [x] Buyer blocked on eBay
- [ ] Google Safe Browsing phishing report
- [ ] Cloudflare abuse report
- [ ] Registrar (OwnRegistrar, Inc.) abuse report
