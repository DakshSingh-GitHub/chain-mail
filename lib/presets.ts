import { EmailAnalysisInput } from './types';

export interface PresetScenario {
  id: string;
  name: string;
  category: 'BEC' | 'Phishing' | 'Malware' | 'Account Takeover' | 'Legitimate';
  threatLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Clean';
  description: string;
  input: EmailAnalysisInput;
}

export const PRESET_SCENARIOS: PresetScenario[] = [
  {
    id: 'bec-wire-transfer',
    name: 'Executive Impersonation & Wire Diversion (BEC)',
    category: 'BEC',
    threatLevel: 'Critical',
    description: 'CEO display name spoofing requesting urgent confidential wire transfer to a newly changed offshore escrow account.',
    input: {
      raw_headers: `Delivered-To: victim-cfo@acmecorp-global.com
Received: by 2002:a17:902:d00d:b0:1c8:774a:9a12 with SMTP id e18csp1928375pld;
        Fri, 28 Aug 2026 14:22:15 -0700 (PDT)
X-Google-Smtp-Source: AGHT+IF9q0X3k4Z2hL5M9a=
X-Received: by 2002:a05:6512:1189:b0:533:f91a:90c8 with SMTP id v9-20020a056512118900b00533f91a90c8mr1847127lfe.4.1724880135112;
        Fri, 28 Aug 2026 14:22:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724880135; cv=none;
        d=google.com; s=arc-20240605;
        b=N5w2G+Z1xK8v...
Received: from mail-relay-04.secureshield-mx.net (mail-relay-04.secureshield-mx.net. [198.51.100.44])
        by mx.google.com with ESMTPS id j12-20020a056512048c00b00533bb27680bsi2948194lfe.129.2026.08.28.14.22.14
        for <victim-cfo@acmecorp-global.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 28 Aug 2026 14:22:14 -0700 (PDT)
Received: from vps-bulletproof-node89.offshore-host.ru (unknown [185.220.101.5])
        by mail-relay-04.secureshield-mx.net (Postfix) with ESMTPA id 4WzT8q2KjLz1
        for <victim-cfo@acmecorp-global.com>; Fri, 28 Aug 2026 21:22:10 +0000 (UTC)
Authentication-Results: mx.google.com;
       dkim=neutral (bad signature) header.i=@acmecorp-globaI.com header.s=default header.b=X9bK2f;
       spf=softfail (google.com: domain of transitioning ceo-direct@acmecorp-globaI.com does not designate 185.220.101.5 as permitted sender) smtp.mailfrom=ceo-direct@acmecorp-globaI.com;
       dmarc=fail (p=none sp=none dis=none) header.from=acmecorp-globaI.com
Return-Path: <ceo-direct@acmecorp-globaI.com>
From: "Marcus Vance (CEO)" <marcus.vance@acmecorp-globaI.com>
Reply-To: "Marcus Vance" <marcus.vance.exec@protonmail-offshore.ch>
To: "Sarah Jenkins (CFO)" <victim-cfo@acmecorp-global.com>
Subject: URGENT: Acquisition Settlement - Wire Instructions (STRICTLY CONFIDENTIAL)
Date: Fri, 28 Aug 2026 21:22:08 +0000
Message-ID: <20260828212208.77192.qmail@vps-bulletproof-node89.offshore-host.ru>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
X-Originating-IP: [185.220.101.5]
X-Priority: 1 (Highest)`,
      email_body: `Sarah,

I am currently in an all-day confidential executive board committee meeting regarding the Project Vanguard acquisition and cannot take phone calls. 

Due to immediate regulatory closing deadlines that expire at 5:00 PM EST today, our lead counsel advised that we must immediately execute the initial escrow retainer of $485,000.00 USD. 

The vendor's primary bank account is under statutory audit, so our M&A intermediary has designated the following updated custodial routing coordinates:

Beneficiary: Apex Global Custody & Escrow Ltd
Bank: Zurich International Commercial Bank (Geneva Branch)
IBAN: CH9300762011623852910
SWIFT/BIC: ZURICHCHGGXXX
Reference: PROJECT-VANGUARD-SETTLEMENT-RETAINER-485K

Please treat this with maximum urgency and confidentiality. Do NOT contact anyone on the financial team or discuss this internally until the press release goes out tomorrow morning. 

Reply directly to this email with the wire transaction confirmation receipt as soon as the funds are queued.

Best regards,

Marcus Vance
Chief Executive Officer
Acme Corp Global`,
      metadata: {
        enriched_ip: "185.220.101.5",
        whois_registrar: "Panama Registrar Inc / Offshore Privacy Ltd",
        domain_age_days: 3,
        threat_feed_hits: ["TOR_EXIT_NODE_ACTIVE", "SPAMHAUS_DROP", "ABUSEIPDB_CONFIDENCE_98%"],
        custom_tags: ["Executive Impersonation", "Typosquatting acmecorp-globaI (Capital I instead of l)"]
      }
    }
  },
  {
    id: 'm365-credential-phishing',
    name: 'Microsoft 365 Credential Harvesting Spear Phish',
    category: 'Phishing',
    threatLevel: 'Critical',
    description: 'Deceptive IT notification mimicking Microsoft 365 security alert directing victim to an Evilginx reverse proxy credential harvester.',
    input: {
      raw_headers: `Delivered-To: dev-team@techcorp.io
Received: by 2002:a05:6830:1584:b0:6fa:4812:1102 with SMTP id n4csp89271;
        Sat, 29 Aug 2026 09:14:02 -0400 (EDT)
Received: from relay-inbound-02.cloudflare.net (relay-inbound-02.cloudflare.net. [172.67.149.88])
        by mx.techcorp.io with ESMTPS id u89si92837190pfa.32.2026.08.29.09.14.01
        for <dev-team@techcorp.io>;
        Sat, 29 Aug 2026 09:14:01 -0400 (EDT)
Received: from mail-node-77.cloud-vps-direct.net (unknown [194.26.29.132])
        by relay-inbound-02.cloudflare.net with ESMTP id 9Xk82Lq1;
        Sat, 29 Aug 2026 13:13:58 +0000
Authentication-Results: mx.techcorp.io;
       dkim=fail reason="signature verification failed" header.i=@microsoft-security-auth-check.com header.s=selector1;
       spf=fail (techcorp.io: domain of security-alert@microsoft-security-auth-check.com does not designate 194.26.29.132 as permitted sender) smtp.mailfrom=security-alert@microsoft-security-auth-check.com;
       dmarc=fail (p=reject) header.from=microsoft-security-auth-check.com
Return-Path: <bounce@microsoft-security-auth-check.com>
From: "Microsoft 365 Security Team" <security-alert@microsoft-security-auth-check.com>
Reply-To: "M365 Identity Support" <no-reply-session-988@tutanota.com>
To: <dev-team@techcorp.io>
Subject: [ACTION REQUIRED] Immediate Password Expiration & Suspicious Sign-in Prevention (Session #8921-99)
Date: Sat, 29 Aug 2026 13:13:50 +0000
Message-ID: <01000191-9921-482a-89bc-992817462819@microsoft-security-auth-check.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
X-Originating-IP: [194.26.29.132]`,
      email_body: `<div style="font-family: 'Segoe UI', Helvetica, Arial, sans-serif; background-color: #f3f2f1; padding: 24px;">
  <div style="max-width: 580px; margin: 0 auto; background: #ffffff; border: 1px solid #e1dfdd; border-radius: 4px; padding: 32px;">
    <img src="https://upload.wikimedia.org/wikipedia/commons/4/44/Microsoft_logo.svg" width="108" alt="Microsoft" style="margin-bottom: 20px;" />
    <h2 style="color: #d83b01; font-size: 20px; font-weight: 600; margin-top: 0;">Security Alert: Microsoft 365 Session Revocation Pending</h2>
    <p style="color: #323130; font-size: 14px; line-height: 1.6;">We detected 3 anomalous sign-in attempts to your enterprise Azure Active Directory account from an unrecognized IP in Saint Petersburg, Russia.</p>
    <p style="color: #323130; font-size: 14px; line-height: 1.6;">To prevent immediate suspension of your Microsoft 365 cloud apps, Exchange Online, and OneDrive workspace, you must verify your identity within <strong>2 hours</strong>.</p>
    <div style="margin: 28px 0; text-align: center;">
      <a href="https://login.microsoftonline.com.account-verification-portal892.xyz/auth/oauth2/v2.0/authorize?client_id=sec89" style="background-color: #0078d4; color: #ffffff; padding: 12px 28px; text-decoration: none; border-radius: 2px; font-weight: 600; display: inline-block;">Keep Current Password & Verify Identity</a>
    </div>
    <p style="color: #605e5c; font-size: 12px; border-top: 1px solid #edebe9; padding-top: 16px; margin-top: 24px;">Microsoft Corporation, One Microsoft Way, Redmond, WA 98052 USA | Enterprise Security Automated Notification</p>
  </div>
</div>`,
      metadata: {
        enriched_ip: "194.26.29.132",
        whois_registrar: "NameCheap / Withheld for Privacy",
        domain_age_days: 1,
        threat_feed_hits: ["PHISHTANK_VERIFIED", "URLHAUS_ACTIVE", "CRIMINAL_IP_PROXY"],
        custom_tags: ["Evilginx2 Reverse Proxy", "M365 Brand Abuse", "Subdomain Deception"]
      }
    }
  },
  {
    id: 'malicious-invoice-payload',
    name: 'Malicious Invoice & Disguised ISO Dropper',
    category: 'Malware',
    threatLevel: 'Critical',
    description: 'Overdue billing notification spoofing QuickBooks with disguised malicious LNK/ISO container delivering infostealer loader.',
    input: {
      raw_headers: `Delivered-To: accounts-payable@fintech-partners.com
Received: by 2002:a05:620a:2088:b0:771:8829:4411 with SMTP id c8csp19028;
        Sun, 30 Aug 2026 04:18:22 -0700 (PDT)
Received: from mx-cloud-filter.mimecast-mail.com (mx-cloud-filter.mimecast-mail.com. [205.139.110.20])
        by mx.fintech-partners.com with ESMTPS id d99si1928471
        for <accounts-payable@fintech-partners.com>;
        Sun, 30 Aug 2026 04:18:21 -0700 (PDT)
Received: from outbound-smtp.bullet-vps.cz (unknown [45.154.255.89])
        by mx-cloud-filter.mimecast-mail.com with ESMTP id 8K9p0Z;
        Sun, 30 Aug 2026 11:18:18 +0000
Authentication-Results: mx.fintech-partners.com;
       dkim=none (no signature found);
       spf=softfail (fintech-partners.com: 45.154.255.89 is not permitted by domain quickbooks-billing-service.online) smtp.mailfrom=notifications@quickbooks-billing-service.online;
       dmarc=fail (p=none) header.from=quickbooks-billing-service.online
Return-Path: <bounce-99128@quickbooks-billing-service.online>
From: "Intuit QuickBooks Notification" <quickbooks-invoice@quickbooks-billing-service.online>
Reply-To: "Collections Department" <billing-disputes-helpdesk@yandex.com>
To: "Accounts Payable" <accounts-payable@fintech-partners.com>
Subject: FINAL NOTICE: Overdue Invoice #INV-2026-884129 ($18,420.00) - Legal Action Pending
Date: Sun, 30 Aug 2026 11:18:15 +0000
Message-ID: <89102837.20260830111815@quickbooks-billing-service.online>
Content-Type: multipart/mixed; boundary="----=_Part_99182_771829"
X-Originating-IP: [45.154.255.89]`,
      email_body: `Dear Valued Customer,

Please find attached your updated statement and final demand notice for overdue Invoice #INV-2026-884129 in the total outstanding sum of $18,420.00 USD.

Our legal collection agency has instructed us to initiate formal commercial litigation and place a lien on your merchant account if payment is not finalized by close of business today.

To inspect the itemized ledger and remittance voucher, open the attached certified billing archive:
Attachment: Invoice_INV_2026_884129_PDF.iso (SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)

If you have already paid this invoice, please review the attached reconciliation document immediately to resolve the accounting mismatch.

Intuit QuickBooks Enterprise Billing Solutions
Toll Free: 1-800-555-0199 (Ext 410)`,
      metadata: {
        enriched_ip: "45.154.255.89",
        whois_registrar: "Reg.ru / Anonymous Proxy",
        domain_age_days: 4,
        threat_feed_hits: ["ALIENTAULT_OTX_PULSE_LUMMA", "ABUSEIPDB_100%", "C2_INFRASTRUCTURE"],
        custom_tags: ["Disguised ISO Container", "Infostealer Payload Dropper", "LummaC2 Pattern"]
      }
    }
  },
  {
    id: 'compromised-vendor-mailbox',
    name: 'Compromised Vendor Mailbox (Account Takeover)',
    category: 'Account Takeover',
    threatLevel: 'High',
    description: 'Legitimate vendor domain and valid DKIM/SPF signatures, but sent via an anomalous residential proxy with fraudulent banking routing details.',
    input: {
      raw_headers: `Delivered-To: procurement@enterprise-retail.com
Received: by 2002:a05:6a00:1c88:b0:5f0:9281:18a9 with SMTP id f8csp28471;
        Sat, 29 Aug 2026 18:04:12 -0700 (PDT)
Received: from mail-ed1-f41.google.com (mail-ed1-f41.google.com. [209.85.208.41])
        by mx.google.com with ESMTPS id h19-20020a056a00161300b005e83918b993si182749lfa.21.2026.08.29.18.04.11
        for <procurement@enterprise-retail.com>;
        Sat, 29 Aug 2026 18:04:11 -0700 (PDT)
Received: from 104.28.212.18 (unknown [185.246.128.45])
        by smtp.gmail.com with ESMTPSA id q12sm1827491pfc.38.2026.08.29.18.04.09
        for <procurement@enterprise-retail.com>;
        Sat, 29 Aug 2026 18:04:09 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@reliable-logistics-partner.com header.s=google header.b=K8zY1q;
       spf=pass (google.com: domain of billing@reliable-logistics-partner.com designates 209.85.208.41 as permitted sender) smtp.mailfrom=billing@reliable-logistics-partner.com;
       dmarc=pass (p=reject sp=reject dis=none) header.from=reliable-logistics-partner.com
Return-Path: <billing@reliable-logistics-partner.com>
From: "David Chen (Reliable Logistics)" <billing@reliable-logistics-partner.com>
Reply-To: "David Chen" <david.chen.logistics@mail-gateway-forwarder.cc>
To: "Procurement Team" <procurement@enterprise-retail.com>
Subject: Re: Monthly Freight Settlement Q3 - Updated Remittance Banking Coordinates
Date: Sun, 30 Aug 2026 01:04:05 +0000
Message-ID: <CABk9q2=M+Zk9Q8u172498274812@mail.gmail.com>
X-Originating-IP: [185.246.128.45]`,
      email_body: `Hi Mark,

Hope you are having a great weekend.

Following up on our invoice settlement for the August container shipping charges ($92,400.00). 

Please note that our corporate treasury has transitioned our receivables to Wells Fargo Commercial Escrow due to our mid-year banking consolidation. Please ensure the payment due this Monday is sent to the new banking instructions attached below:

Beneficiary: Reliable Logistics Partner LLC
Bank: Pacific Commercial Escrow Bank
Account Number: 9821-4401-2918
Routing (ABA): 121000358
Swift: PACBUS33

Please confirm receipt and acknowledge that your accounting portal has been updated accordingly.

Thanks,
David Chen
Finance Director | Reliable Logistics Partner`,
      metadata: {
        enriched_ip: "185.246.128.45",
        whois_registrar: "MarkMonitor (Clean Domain, 8 years old)",
        domain_age_days: 3120,
        threat_feed_hits: ["RESIDENTIAL_PROXY_SOCKS5", "NIGERIA_GEOLOCATION_DISCREPANCY"],
        custom_tags: ["Vendor Account Takeover (ATO)", "Reply-To Diverted", "Anomalous Originating Client IP"]
      }
    }
  },
  {
    id: 'legitimate-corporate-transactional',
    name: 'Verified Legitimate Corporate Transactional',
    category: 'Legitimate',
    threatLevel: 'Clean',
    description: 'Fully authenticated corporate communication with valid cryptographic signatures, matching SPF/DKIM/DMARC alignments, and reputable enterprise MTA.',
    input: {
      raw_headers: `Delivered-To: employee@acme-corp.com
Received: by 2002:a17:906:8492:b0:938:2910:aa11 with SMTP id y18csp192837;
        Sun, 30 Aug 2026 08:30:15 -0700 (PDT)
Received: from mail-qk1-x732.google.com (mail-qk1-x732.google.com. [2607:f8b0:4864:20::732])
        by mx.google.com with ESMTPS id o18si829104qka.11.2026.08.30.08.30.14
        for <employee@acme-corp.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 30 Aug 2026 08:30:14 -0700 (PDT)
Received: by mail-qk1-x732.google.com with SMTP id 4y28-20020a170906849200b009382910aa11mr182749qka.18.1725031814281;
        Sun, 30 Aug 2026 08:30:14 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@github.com header.s=pf2024 header.b=bK89zX;
       spf=pass (google.com: domain of noreply@github.com designates 2607:f8b0:4864:20::732 as permitted sender) smtp.mailfrom=noreply@github.com;
       dmarc=pass (p=reject sp=reject dis=none) header.from=github.com
Return-Path: <noreply@github.com>
From: "GitHub" <noreply@github.com>
Reply-To: "GitHub Support" <support@github.com>
To: <employee@acme-corp.com>
Subject: [GitHub] Pull Request #342 Merged: feat(core): add RFC 5322 parser
Date: Sun, 30 Aug 2026 15:30:12 +0000
Message-ID: <github/chain-mail/pull/342/merged@github.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"`,
      email_body: `Hi @dakshdts,

Pull Request #342 ("feat(core): add RFC 5322 parser") was successfully reviewed, approved, and merged into main by @lead-architect.

Branch: main
Commit: 7f3a90c21980
All 42 continuous integration tests passed successfully.

View Pull Request on GitHub:
https://github.com/chain-mail/platform/pull/342

---
You are receiving this email because you authored the pull request.
Manage your GitHub notification preferences at https://github.com/settings/notifications`,
      metadata: {
        enriched_ip: "140.82.121.4",
        whois_registrar: "MarkMonitor / GitHub Inc.",
        domain_age_days: 6200,
        threat_feed_hits: [],
        custom_tags: ["Verified Enterprise", "DMARC Reject Enforced"]
      }
    }
  }
];

