# A04 — Insecure Design (business logic)

## The point
Not every attack is a payload. Some are ordinary requests that break a rule the
app never enforced. Checkout with quantity -5 against a positive unit price is a
refund/credit abuse. The HTTP is clean. The flaw is the missing rule.

## Why the WAF is blind
A WAF matches malicious content. `{"sku":"sku-blue-shoe","qty":-5}` has none.
Quantity -5 is a valid integer. The WAF has no model of your business, so it
cannot know that -5 is nonsense. Business-logic defense lives only in the app.

## What the app does
Checkout prices from a server-side catalog and bounds quantity to 1..10. A
negative or out-of-range quantity, an unknown SKU, or a client-supplied price is
rejected and logged as an OCSF API Activity event (6003, status Failure) with
the reason. Pricing on the client side would be the same class of flaw.

## The detection
`detections/business_logic.yml` matches the 6003 business-rule failure.
`test.sh` sends qty -5 (fires) and qty 2 (silent). Durable detections for A04
are built from the app's own rules, not from signatures.
