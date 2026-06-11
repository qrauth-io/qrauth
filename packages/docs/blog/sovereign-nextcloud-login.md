---
title: Sovereign sign-in for Nextcloud
description: QRAuth is a certified OpenID Provider. Add QR scan-to-login to a stock Nextcloud through the standard user_oidc app — sovereign, standards-based, no lock-in.
head:
  - - meta
    - property: og:title
      content: Sovereign sign-in for Nextcloud
  - - meta
    - property: og:description
      content: QRAuth is a certified OpenID Provider. Add QR scan-to-login to a stock Nextcloud through the standard user_oidc app — sovereign, standards-based, no lock-in.
  - - meta
    - property: og:type
      content: article
  - - meta
    - property: og:url
      content: https://docs.qrauth.io/blog/sovereign-nextcloud-login.html
  - - meta
    - property: og:image
      content: https://docs.qrauth.io/logo.svg
  - - meta
    - property: og:site_name
      content: QRAuth
  - - meta
    - name: twitter:card
      content: summary
  - - meta
    - name: twitter:title
      content: Sovereign sign-in for Nextcloud
  - - meta
    - name: twitter:description
      content: QRAuth is a certified OpenID Provider. Add QR scan-to-login to a stock Nextcloud through the standard user_oidc app — sovereign, standards-based, no lock-in.
  - - meta
    - name: twitter:image
      content: https://docs.qrauth.io/logo.svg
---

# Sovereign sign-in for Nextcloud

Last week, Europe launched Euro-Office — a sovereign office suite. Within
days, critics pointed at the parts of the stack nobody had answered for yet:
hosting, build systems, supply chain, and authentication. They were right to
ask. A sovereign office suite signed in through someone else's identity
infrastructure is a house with someone else's key in the lock.

Authentication is the part we can answer for. Today.

## What this is

QRAuth is a certified OpenID Provider — OpenID Certified™ for the Basic OP
and Config OP profiles, listed by the OpenID Foundation. Nextcloud ships an
official OpenID Connect backend (`user_oidc`). Put the two together and your
Nextcloud gets QR scan-to-login: open your Nextcloud, scan the code with your
phone, you are in. No passwords typed, no password database to breach, no
US-based identity broker in the path.

We tested it end to end against a stock Nextcloud and the standard
`user_oidc` app — no patches, no custom code. The full setup is one client
registration and one `occ` command. The guide takes about ten minutes:
[Sign in to Nextcloud with QRAuth](https://docs.qrauth.io/guide/nextcloud.html).

## Why it qualifies as sovereign

We do not ask you to take the word "sovereign" on faith, so here is what
stands behind it. QRAuth is built and operated in Greece by an independent
European team. The identity protocol is OpenID Connect — an open standard,
certified by the OpenID Foundation's conformance suite, so you are
integrating against a standard, not against us. Per-client pairwise
identifiers mean relying parties cannot correlate your users across sites.
And because it is standard OIDC, leaving is as easy as arriving: point your
`user_oidc` config at a different provider and you are gone. Lock-in is the
opposite of sovereignty, so we built none.

## Free for the people who should have it free

Accredited academic institutions, registered non-profits, and open-source
projects get Pro free of charge. Email us with a brief description of your
institution or project. A university running Nextcloud for ten thousand
students pays nothing for sign-in.

## Get started

Register a sign-in client in the [QRAuth dashboard](https://qrauth.io/dashboard/sign-in-clients),
follow the [Nextcloud guide](https://docs.qrauth.io/guide/nextcloud.html),
and your users scan to log in. If you run OpenProject, XWiki, or anything
else that speaks OpenID Connect, the same provider works there too.
