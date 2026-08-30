import { EmailAnalysisInput, ThreatClassification } from './types';

export interface EmailRecord {
  id: string;
  subject: string;
  senderName: string;
  senderEmail: string;
  displayDomain: string;
  actualDomain: string;
  recipient: string;
  date: string;
  category: ThreatClassification;
  isSpoofed: boolean;
  threatLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Clean';
  simulatedRisk: number;
  originIp: string;
  originCountry: string;
  snippet: string;
  input: EmailAnalysisInput;
}

// Templates for creating realistic 100 emails
interface TemplateDef {
  category: ThreatClassification;
  isSpoofed: boolean;
  threatLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Clean';
  subject: string;
  senderName: string;
  senderEmail: string;
  replyTo?: string;
  originIp: string;
  country: string;
  isp: string;
  body: string;
  spf: 'pass' | 'fail' | 'softfail' | 'neutral';
  dkim: 'pass' | 'fail' | 'none';
  dmarc: 'pass' | 'fail';
  domainAge: number;
}

const TEMPLATES: TemplateDef[] = [
  // BEC Templates
  {
    category: 'BEC',
    isSpoofed: true,
    threatLevel: 'Critical',
    subject: 'URGENT: Acquisition Settlement - Wire Instructions (STRICTLY CONFIDENTIAL)',
    senderName: 'Marcus Vance (CEO)',
    senderEmail: 'marcus.vance@acmecorp-globaI.com',
    replyTo: 'marcus.vance.exec@protonmail-offshore.ch',
    originIp: '185.220.101.5',
    country: 'Russian Federation',
    isp: 'Tor Exit Relay / Offshore Host Ltd',
    spf: 'softfail',
    dkim: 'fail',
    dmarc: 'fail',
    domainAge: 3,
    body: 'Sarah, I am in an all-day confidential board meeting regarding Project Vanguard. Due to closing deadlines expiring at 5 PM today, lead counsel advised wiring $485,000.00 USD to the updated custodial escrow coordinates immediately. Reply directly with confirmation.'
  },
  {
    category: 'BEC',
    isSpoofed: true,
    threatLevel: 'Critical',
    subject: 'Re: Vendor Payment Schedule Adjustment - Updated Account Info',
    senderName: 'David Chen (Reliable Logistics)',
    senderEmail: 'billing@reliable-logistics-partner.com',
    replyTo: 'david.chen.logistics@mail-gateway-forwarder.cc',
    originIp: '185.246.128.45',
    country: 'Nigeria',
    isp: 'Spectranet 4G LTE Residential SOCKS5',
    spf: 'pass',
    dkim: 'pass',
    dmarc: 'pass',
    domainAge: 3120,
    body: 'Hi Mark, Following up on our invoice settlement for $92,400.00. Our treasury has transitioned receivables to Wells Fargo Commercial Escrow due to mid-year banking consolidation. Please ensure payment due Monday is routed to our new coordinates.'
  },
  {
    category: 'BEC',
    isSpoofed: true,
    threatLevel: 'High',
    subject: 'Direct Deposit / Payroll Routing Change Request - Urgent',
    senderName: 'Elena Rostova (VP Operations)',
    senderEmail: 'elena.rostova@corphq-humanresources.org',
    replyTo: 'elena.rostova.private@tutanota.de',
    originIp: '194.26.29.132',
    country: 'Bulgaria',
    isp: 'CloudVPS FastRoute Networks',
    spf: 'fail',
    dkim: 'fail',
    dmarc: 'fail',
    domainAge: 5,
    body: 'Hello HR Team, I recently switched banking providers and need my direct deposit payroll allocation updated before the 1st of the month. Attached are my new checking account voided checks.'
  },
  {
    category: 'BEC',
    isSpoofed: true,
    threatLevel: 'Critical',
    subject: 'CONFIDENTIAL: Q3 Legal Retainer Wire Authorization ($340,000.00)',
    senderName: 'Arthur Pendelton (Managing Partner)',
    senderEmail: 'arthur.pendelton@Iw-legal-counsel.com',
    replyTo: 'pendelton-attorneys@mail-hub-direct.ru',
    originIp: '45.154.255.89',
    country: 'Czech Republic',
    isp: 'Flyservers Dedicated Ltd',
    spf: 'softfail',
    dkim: 'fail',
    dmarc: 'fail',
    domainAge: 2,
    body: 'Please authorize and release the legal retainer wire of $340,000.00 to the court-appointed escrow trustees at Zurich International. Speed is of the essence to avoid statutory injunction.'
  },

  // Phishing Templates
  {
    category: 'Phishing',
    isSpoofed: true,
    threatLevel: 'Critical',
    subject: '[ACTION REQUIRED] Immediate Password Expiration & Suspicious Sign-in Prevention',
    senderName: 'Microsoft 365 Security Team',
    senderEmail: 'security-alert@microsoft-security-auth-check.com',
    replyTo: 'no-reply-session-988@tutanota.com',
    originIp: '194.26.29.132',
    country: 'Bulgaria',
    isp: 'CloudVPS FastRoute Networks',
    spf: 'fail',
    dkim: 'fail',
    dmarc: 'fail',
    domainAge: 1,
    body: 'We detected 3 anomalous sign-in attempts to your Microsoft 365 Azure AD account from Saint Petersburg. To prevent suspension, verify your identity within 2 hours: https://login.microsoftonline.com.account-verification-portal892.xyz/auth'
  },
  {
    category: 'Phishing',
    isSpoofed: true,
    threatLevel: 'High',
    subject: 'DocuSign: Please DocuSign & Review Employment Confidentiality Agreement',
    senderName: 'DocuSign Electronic Delivery',
    senderEmail: 'dse@docusign-verification-docs99.com',
    replyTo: 'support@docusign-verification-docs99.com',
    originIp: '185.220.101.5',
    country: 'Russian Federation',
    isp: 'Tor Exit Relay / Offshore Host Ltd',
    spf: 'fail',
    dkim: 'fail',
    dmarc: 'fail',
    domainAge: 4,
    body: 'You have received an electronic signature request from Legal HR. Click here to review and authenticate your corporate credentials to sign: https://docusign.com.review-document-auth99.cc/sign/8821'
  },
  {
    category: 'Phishing',
    isSpoofed: true,
    threatLevel: 'High',
    subject: 'AWS Security Alert: Root Account Access Key Compromise Detected',
    senderName: 'Amazon Web Services Notification',
    senderEmail: 'no-reply@aws-security-identity-center.net',
    originIp: '45.154.255.89',
    country: 'Czech Republic',
    isp: 'Flyservers Dedicated Ltd',
    spf: 'fail',
    dkim: 'fail',
    dmarc: 'fail',
    domainAge: 2,
    body: 'Your AWS account 4910-8821-9921 root API keys were accessed from an unauthorized region. Re-verify your MFA device and rotate credentials now: https://aws.amazon.com.iam-reauth-portal.online/mfa'
  },
  {
    category: 'Phishing',
    isSpoofed: true,
    threatLevel: 'High',
    subject: 'Stripe: Action Required - Your Payouts Have Been Paused',
    senderName: 'Stripe Merchant Operations',
    senderEmail: 'notices@stripe-merchant-verification-eu.com',
    originIp: '194.26.29.132',
    country: 'Bulgaria',
    isp: 'CloudVPS FastRoute Networks',
    spf: 'fail',
    dkim: 'fail',
    dmarc: 'fail',
    domainAge: 6,
    body: 'Due to updated European banking compliance guidelines, your incoming Stripe customer payouts ($42,180.00) have been placed on 48-hour hold. Re-submit your merchant identity verification.'
  },

  // Malware & Disguised Dropper Templates
  {
    category: 'Suspicious',
    isSpoofed: true,
    threatLevel: 'Critical',
    subject: 'FINAL NOTICE: Overdue Invoice #INV-2026-884129 ($18,420.00) - Legal Action Pending',
    senderName: 'Intuit QuickBooks Notification',
    senderEmail: 'quickbooks-invoice@quickbooks-billing-service.online',
    replyTo: 'billing-disputes-helpdesk@yandex.com',
    originIp: '45.154.255.89',
    country: 'Czech Republic',
    isp: 'Flyservers Dedicated Ltd',
    spf: 'softfail',
    dkim: 'none',
    dmarc: 'fail',
    domainAge: 4,
    body: 'Please find attached your updated statement and final demand notice for overdue Invoice #INV-2026-884129 in the total sum of $18,420.00 USD. Inspect the itemized ledger: Attachment: Invoice_INV_2026_884129_PDF.iso'
  },
  {
    category: 'Suspicious',
    isSpoofed: true,
    threatLevel: 'Critical',
    subject: 'DHL Express: Shipping Waybill Exception Notification #DHL-992182-US',
    senderName: 'DHL Express Delivery Portal',
    senderEmail: 'tracking@dhl-delivery-customs-clearance.cc',
    originIp: '185.220.101.5',
    country: 'Russian Federation',
    isp: 'Tor Exit Relay / Offshore Host Ltd',
    spf: 'fail',
    dkim: 'fail',
    dmarc: 'fail',
    domainAge: 3,
    body: 'Your international parcel #DHL-992182 cannot be released by customs without payment of import excise fee ($14.20). Open the attached receipt statement: Shipping_Manifest_Receipt.zip'
  },

  // Legitimate / Safe Templates
  {
    category: 'Legitimate',
    isSpoofed: false,
    threatLevel: 'Clean',
    subject: '[GitHub] Pull Request #342 Merged: feat(core): add RFC 5322 parser',
    senderName: 'GitHub',
    senderEmail: 'noreply@github.com',
    originIp: '140.82.121.4',
    country: 'United States',
    isp: 'GitHub Inc. / Microsoft Corp.',
    spf: 'pass',
    dkim: 'pass',
    dmarc: 'pass',
    domainAge: 6200,
    body: 'Hi @dakshdts, Pull Request #342 was successfully reviewed, approved, and merged into main by @lead-architect. All 42 continuous integration tests passed.'
  },
  {
    category: 'Legitimate',
    isSpoofed: false,
    threatLevel: 'Clean',
    subject: 'Your Google Cloud Monthly Invoice #GCP-2026-08 ($314.80 USD)',
    senderName: 'Google Cloud Platform',
    senderEmail: 'cloud-billing-noreply@google.com',
    originIp: '209.85.208.41',
    country: 'United States',
    isp: 'Google LLC',
    spf: 'pass',
    dkim: 'pass',
    dmarc: 'pass',
    domainAge: 9800,
    body: 'Hello Cloud Administrator, Your monthly billing statement for project "enterprise-threat-engine-prod" is available. Total charges: $314.80 charged to corporate Amex ending in 4018.'
  },
  {
    category: 'Legitimate',
    isSpoofed: false,
    threatLevel: 'Clean',
    subject: 'Slack Daily Summary: 14 unread mentions in #security-incident-response',
    senderName: 'Slack Notifications',
    senderEmail: 'notification@slack.com',
    originIp: '54.240.14.88',
    country: 'United States',
    isp: 'Slack Technologies / Amazon AWS',
    spf: 'pass',
    dkim: 'pass',
    dmarc: 'pass',
    domainAge: 4500,
    body: 'Here is what happened while you were away in your workspace: 14 mentions in #security-incident-response, 3 new threads in #threat-intel.'
  },
  {
    category: 'Legitimate',
    isSpoofed: false,
    threatLevel: 'Clean',
    subject: 'Jira Service Management: Ticket #SEC-892 (Firewall Policy Review) Approved',
    senderName: 'Atlassian Cloud Jira',
    senderEmail: 'jira@acme-corp.atlassian.net',
    originIp: '185.166.142.20',
    country: 'Australia',
    isp: 'Atlassian Pty Ltd',
    spf: 'pass',
    dkim: 'pass',
    dmarc: 'pass',
    domainAge: 5100,
    body: 'Ticket SEC-892: "Review edge perimeter firewall drop rules for RFC 5322 incoming proxies" has been transitioned to RESOLVED by Principal SecOps Engineer.'
  },
  {
    category: 'Legitimate',
    isSpoofed: false,
    threatLevel: 'Clean',
    subject: 'Zoom Video Communications: Weekly Team Sync Invitation for Mon 10:00 AM',
    senderName: 'Zoom Cloud Meetings',
    senderEmail: 'no-reply@zoom.us',
    originIp: '3.211.240.11',
    country: 'United States',
    isp: 'Zoom Video Communications Inc',
    spf: 'pass',
    dkim: 'pass',
    dmarc: 'pass',
    domainAge: 4800,
    body: 'Hi Team, You have been invited to the recurring Weekly Security Triage & Sprint Planning meeting. Meeting ID: 891 0291 4410.'
  }
];

// Generate 100 unique email records deterministically
export function generate100Emails(): EmailRecord[] {
  const emails: EmailRecord[] = [];
  const count = 100;

  for (let i = 1; i <= count; i++) {
    const templateIndex = (i - 1) % TEMPLATES.length;
    const t = TEMPLATES[templateIndex];

    const id = `EML-${i.toString().padStart(3, '0')}`;
    const dateStr = `Sun, 30 Aug 2026 ${10 + (i % 12)}:${(i * 7) % 60}:00 +0000`;

    // Compute simulated risk
    let simulatedRisk = 0;
    if (t.category === 'BEC') simulatedRisk = 90 + (i % 9);
    else if (t.category === 'Phishing') simulatedRisk = 85 + (i % 12);
    else if (t.category === 'Suspicious' || t.category === 'Impersonation') simulatedRisk = 75 + (i % 15);
    else simulatedRisk = 2 + (i % 4);

    const fromDomain = t.senderEmail.split('@')[1] || 'domain.com';
    const replyToDomain = t.replyTo ? (t.replyTo.split('@')[1] || fromDomain) : fromDomain;

    const rawHeaders = `Delivered-To: victim-analyst@acme-corp.com
Received: by 2002:a17:902:d00d:b0:1c8:774a:9a12 with SMTP id e18csp${100000 + i};
        ${dateStr}
Received: from mail-relay-gateway.net (mail-relay-gateway.net. [198.51.100.44])
        by mx.google.com with ESMTPS id j12-${1000 + i}
        for <victim-analyst@acme-corp.com>;
        ${dateStr}
Received: from host-client-${i}.net (unknown [${t.originIp}])
        by mail-relay-gateway.net (Postfix) with ESMTPA id 4WzT8q${i}
        for <victim-analyst@acme-corp.com>; ${dateStr}
Authentication-Results: mx.acme-corp.com;
       dkim=${t.dkim} header.i=@${fromDomain} header.s=default;
       spf=${t.spf} smtp.mailfrom=${t.senderEmail};
       dmarc=${t.dmarc} (p=${t.dmarc === 'pass' ? 'reject' : 'none'}) header.from=${fromDomain}
Return-Path: <${t.senderEmail}>
From: "${t.senderName}" <${t.senderEmail}>
${t.replyTo ? `Reply-To: "${t.senderName}" <${t.replyTo}>\n` : ''}To: "Security Analyst" <victim-analyst@acme-corp.com>
Subject: ${t.subject} (Case #${i})
Date: ${dateStr}
Message-ID: <${i}.20260830.${Math.random().toString(36).substring(2, 8)}@${fromDomain}>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [${t.originIp}]`;

    emails.push({
      id,
      subject: `${t.subject} (Case #${i})`,
      senderName: t.senderName,
      senderEmail: t.senderEmail,
      displayDomain: fromDomain,
      actualDomain: replyToDomain,
      recipient: 'victim-analyst@acme-corp.com',
      date: `Aug 30, 2026 ${10 + (i % 12)}:${((i * 7) % 60).toString().padStart(2, '0')} UTC`,
      category: t.category,
      isSpoofed: t.isSpoofed,
      threatLevel: t.threatLevel,
      simulatedRisk,
      originIp: t.originIp,
      originCountry: t.country,
      snippet: t.body.slice(0, 110) + '...',
      input: {
        raw_headers: rawHeaders,
        email_body: t.body,
        metadata: {
          enriched_ip: t.originIp,
          whois_registrar: t.isSpoofed ? 'Offshore Privacy Ltd' : 'MarkMonitor Inc',
          domain_age_days: t.domainAge,
          threat_feed_hits: t.isSpoofed ? ['TOR_EXIT_NODE_ACTIVE', 'SPAMHAUS_DROP'] : []
        }
      }
    });
  }

  return emails;
}

export const MOCK_100_EMAILS = generate100Emails();

