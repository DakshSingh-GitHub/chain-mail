export type ThreatClassification = 
  | 'Legitimate'
  | 'Suspicious'
  | 'Impersonation'
  | 'Phishing'
  | 'BEC';

export type ConfidenceLevel = 'Low' | 'Medium' | 'High';

export type InfrastructureType = 
  | 'VPN'
  | 'TOR Exit Node'
  | 'Open Relay'
  | 'Botnet'
  | 'Bulletproof Hosting'
  | 'Cloud Infrastructure'
  | 'Residential Proxy'
  | 'Corporate Mail Server'
  | 'Consumer ISP';

export type AccountState = 
  | 'Compromised Legitimate Account'
  | 'Purely Spoofed Domain'
  | 'Direct Malicious Infrastructure'
  | 'Verified Legitimate Infrastructure';

export interface EmailAnalysisInput {
  raw_headers: string;
  email_body: string;
  metadata?: {
    enriched_ip?: string;
    whois_registrar?: string;
    domain_age_days?: number;
    threat_feed_hits?: string[];
    custom_tags?: string[];
    [key: string]: unknown;
  };
}

export interface HeaderHop {
  hop_number: number;
  from_host?: string;
  from_ip?: string;
  by_host?: string;
  protocol?: string;
  timestamp?: string;
  delay_seconds?: number;
  is_earliest_reliable?: boolean;
  is_internal_relay?: boolean;
  is_anomalous?: boolean;
  anomaly_reason?: string;
  geo?: {
    country: string;
    country_code: string;
    city: string;
    isp: string;
    asn: string;
    lat: number;
    lon: number;
  };
}

export interface AuthProtocolResult {
  status: 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NEUTRAL' | 'NONE' | 'TEMPERROR' | 'PERMERROR';
  details: string;
  alignment: 'ALIGNED' | 'MISALIGNED' | 'NOT_APPLICABLE';
  domain?: string;
  selector?: string;
  policy?: 'none' | 'quarantine' | 'reject' | 'unknown';
}

export interface HeaderForensics {
  spf: AuthProtocolResult;
  dkim: AuthProtocolResult;
  dmarc: AuthProtocolResult;
  return_path: string;
  from_header: string;
  reply_to_header: string;
  message_id: string;
  date_header: string;
  detected_spoofing: boolean;
  spoofing_vectors: string[];
  relay_anomalies: string[];
  domain_lookalike: {
    is_lookalike: boolean;
    display_domain: string;
    actual_domain: string;
    technique?: 'Homoglyph' | 'Typosquatting' | 'Subdomain Deception' | 'Display Name Impersonation' | 'None';
  };
  hops: HeaderHop[];
}

export interface NLPAnalysis {
  intent: ThreatClassification;
  urgency_score: number; // 0 - 100
  urgency_cues: string[];
  social_engineering_tactics: string[];
  financial_fraud_patterns: string[];
  impersonation_target?: string;
  detected_links: Array<{
    url: string;
    display_text?: string;
    is_obfuscated: boolean;
    risk_level: 'Low' | 'Medium' | 'High' | 'Critical';
    flags: string[];
  }>;
  attachment_indicators: Array<{
    filename: string;
    extension: string;
    risk_level: 'Low' | 'Medium' | 'High' | 'Critical';
    is_disguised: boolean;
    flags: string[];
  }>;
  summary: string;
}

export interface TraceabilityMap {
  earliest_reliable_ip: string;
  reverse_dns?: string;
  geolocation_estimate: {
    country: string;
    country_code: string;
    region: string;
    city: string;
    latitude: number;
    longitude: number;
    isp: string;
    asn: string;
    timezone: string;
  };
  infrastructure_type: InfrastructureType;
  infrastructure_risk_score: number; // 0 - 100
  infrastructure_flags: string[];
  domain_intelligence: {
    domain: string;
    registrar?: string;
    domain_age_days?: number;
    is_newly_registered: boolean;
    nameservers?: string[];
    mx_records?: string[];
    dmarc_enforced: boolean;
  };
}

export interface ThreatActorProfile {
  name: string;
  aliases: string[];
  category: string;
  motivation: string;
  common_techniques: string[];
  target_sectors: string[];
}

export interface AttributionConfidence {
  account_state: AccountState;
  confidence_level: ConfidenceLevel;
  confidence_score: number; // 0 - 100
  associated_campaign?: string;
  threat_actor?: ThreatActorProfile;
  indicators_of_compromise: Array<{
    type: 'IP' | 'Domain' | 'URL' | 'Email' | 'Hash' | 'Header';
    value: string;
    description: string;
    verdict: 'Malicious' | 'Suspicious' | 'Benign';
  }>;
  forensic_narrative: string;
}

export interface ActionableRecommendation {
  priority: 'Immediate' | 'High' | 'Medium' | 'Low';
  category: 'Network Edge' | 'Identity & Access' | 'Email Gateway' | 'Endpoint & User' | 'Legal & Compliance';
  action: string;
  technical_command?: string;
  rationale: string;
}

export interface HeaderSecurityCheck {
  header_name: string;
  value: string;
  security_status: 'Secure' | 'Warning' | 'Critical Failure';
  explanation: string;
}

export interface AnalysisPipelineStep {
  step_number: number;
  name: string;
  status: 'Passed' | 'Flagged' | 'Warning';
  details: string;
}

export interface ForensicReport {
  incident_id: string;
  timestamp: string;
  threat_classification: ThreatClassification;
  fraud_risk_score: number; // 0 - 100 (0 = completely safe, 100 = extreme threat)
  nlp_analysis: NLPAnalysis;
  header_forensics: HeaderForensics;
  traceability_map: TraceabilityMap;
  attribution_confidence: AttributionConfidence;
  actionable_recommendations: ActionableRecommendation[];
  header_security_checks: HeaderSecurityCheck[];
  analysis_steps: AnalysisPipelineStep[];
  compliance_audit: {
    rfc_5322_compliant: boolean;
    pii_masked: boolean;
    evidence_hash_sha256: string;
  };
  engine_mode?: 'ai-gemini' | 'heuristic-offline';
  model_name?: string;
  analysis_latency_ms?: number;
  ai_reasoning_summary?: string;
}

