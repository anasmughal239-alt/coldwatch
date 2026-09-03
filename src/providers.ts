/**
 * Mail-provider fingerprints, keyed off MX hostnames, plus the DKIM selectors
 * each provider uses by default. DKIM has no enumeration mechanism, so knowing
 * the provider is how we guess the right selector without asking the user.
 */

export interface ProviderProfile {
  id: string;
  name: string;
  /** MX exchange substrings that identify this provider. */
  mxMatch: string[];
  /** Selectors this provider publishes by default, most likely first. */
  dkimSelectors: string[];
}

export const PROVIDERS: ProviderProfile[] = [
  {
    id: "google",
    name: "Google Workspace",
    mxMatch: ["aspmx.l.google.com", "googlemail.com", ".google.com"],
    dkimSelectors: ["google"],
  },
  {
    id: "microsoft365",
    name: "Microsoft 365",
    mxMatch: ["mail.protection.outlook.com"],
    dkimSelectors: ["selector1", "selector2"],
  },
  {
    id: "proofpoint",
    name: "Proofpoint",
    mxMatch: ["pphosted.com", "ppe-hosted.com"],
    dkimSelectors: ["pps1", "selector1", "selector2"],
  },
  {
    id: "mimecast",
    name: "Mimecast",
    mxMatch: ["mimecast.com", "mimecast.co.za"],
    dkimSelectors: ["mimecast", "mimecast20230101"],
  },
  {
    id: "cloudflare",
    name: "Cloudflare Email Routing",
    mxMatch: ["mx.cloudflare.net"],
    dkimSelectors: [],
  },
  {
    id: "zoho",
    name: "Zoho Mail",
    mxMatch: ["zoho.com", "zoho.eu", "zoho.in", "zohomail"],
    dkimSelectors: ["zoho", "zmail"],
  },
  {
    id: "amazonses",
    name: "Amazon SES",
    mxMatch: ["amazonses.com", "inbound-smtp"],
    dkimSelectors: [],
  },
  {
    id: "sendgrid",
    name: "SendGrid",
    mxMatch: ["sendgrid.net", "mx.sendgrid.net"],
    dkimSelectors: ["s1", "s2"],
  },
  {
    id: "mailgun",
    name: "Mailgun",
    mxMatch: ["mailgun.org", "mxa.mailgun.org", "mxb.mailgun.org"],
    dkimSelectors: ["k1", "mx", "smtp", "pic"],
  },
  {
    id: "postmark",
    name: "Postmark",
    mxMatch: ["mtasv.net"],
    dkimSelectors: ["pm", "20230101"],
  },
  {
    id: "fastmail",
    name: "Fastmail",
    mxMatch: ["messagingengine.com"],
    dkimSelectors: ["fm1", "fm2", "fm3"],
  },
  {
    id: "namecheap",
    name: "Namecheap Private Email",
    mxMatch: ["privateemail.com"],
    dkimSelectors: ["default"],
  },
  {
    id: "protonmail",
    name: "Proton Mail",
    mxMatch: ["protonmail.ch", "proton.me"],
    dkimSelectors: ["protonmail", "protonmail2", "protonmail3"],
  },
  {
    id: "yahoo",
    name: "Yahoo / AOL",
    mxMatch: ["yahoodns.net"],
    dkimSelectors: [],
  },
  {
    id: "yandex",
    name: "Yandex 360",
    mxMatch: ["mx.yandex.net", "mx.yandex.ru"],
    dkimSelectors: ["mail"],
  },
  {
    id: "ovh",
    name: "OVHcloud",
    mxMatch: ["mail.ovh.net", "mx.ovh.com"],
    dkimSelectors: ["ovhmo1234567"],
  },
];

/** Selectors to probe when the provider is unknown or publishes none by default. */
export const COMMON_SELECTORS: string[] = [
  "default",
  "dkim",
  "google",
  "selector1",
  "selector2",
  "s1",
  "s2",
  "k1",
  "k2",
  "k3",
  "mail",
  "mxvault",
  "key1",
  "sig1",
  "smtp",
  "mandrill",
  "pm",
  "pic",
  "scph1023",
  "turbo-smtp",
  "zoho",
  "protonmail",
  "fm1",
  "fm2",
  "fm3",
  "mesmtp",
  "dkim1024",
  "everlytickey1",
  "everlytickey2",
];

export function detectProvider(
  mxExchanges: string[],
): ProviderProfile | undefined {
  const lowered = mxExchanges.map((e) => e.toLowerCase());
  for (const p of PROVIDERS) {
    if (p.mxMatch.some((m) => lowered.some((e) => e.includes(m)))) return p;
  }
  return undefined;
}
