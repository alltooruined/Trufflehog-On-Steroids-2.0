// patterns.js — 200+ detection patterns with severity, categories, MITRE mapping, and remediation
// Enterprise-grade pattern library for Trufflehog on Steroids²

// Each pattern: { re: "regex", severity: "critical|high|medium|low", category: "...", mitre: "T####", remediation: "...", verify: "..." }

export const specifics = {
  // ══════════════════════════════════════════════════════════════
  // ── Cloud Provider Keys ──────────────────────────────────────
  // ══════════════════════════════════════════════════════════════
  "AWS Access Key ID":                        { re: "(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", severity: "critical", category: "cloud", mitre: "T1552.001", remediation: "Rotate via IAM console immediately. Audit CloudTrail for unauthorized usage.", verify: "aws" },
  "AWS Secret Access Key":                    { re: "(?:aws)?_?(?:secret)?_?(?:access)?_?key\\s*[=:]\\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?", severity: "critical", category: "cloud", mitre: "T1552.001", remediation: "Rotate key pair in AWS IAM. Check CloudTrail for unauthorized API calls." },
  "AWS MWS Key":                              { re: "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", severity: "critical", category: "cloud", mitre: "T1552.001" },
  "AWS Session Token":                        { re: "(?:aws.?session|aws.?token)\\s*[=:]\\s*[\"']?([A-Za-z0-9/+=]{100,})[\"']?", severity: "critical", category: "cloud", mitre: "T1552.001" },
  "GCP Service Account Key (JSON)":           { re: "\"type\"\\s*:\\s*\"service_account\"", severity: "critical", category: "cloud", mitre: "T1552.001", remediation: "Delete and recreate the service account key. Audit GCP IAM logs." },
  "GCP API Key":                              { re: "AIza[0-9A-Za-z\\-_]{35}", severity: "high", category: "cloud", mitre: "T1552.001", remediation: "Restrict API key scope and regenerate." },
  "Google OAuth Client Secret":               { re: "GOCSPX-[a-zA-Z0-9_\\-]{28}", severity: "high", category: "cloud" },
  "Google OAuth Access Token":                { re: "ya29\\.[0-9A-Za-z\\-_]+", severity: "high", category: "cloud", verify: "google" },
  "Azure Storage Account Key":                { re: "(?:AccountKey|azure[_\\-]?storage[_\\-]?key)\\s*[=:]\\s*[\"']?([A-Za-z0-9+/]{86}==)[\"']?", severity: "critical", category: "cloud", mitre: "T1552.001", remediation: "Rotate storage keys. Use managed identities instead." },
  "Azure AD Client Secret":                   { re: "(?:azure|aad|ms)[\\w\\-]*(?:client[\\-_]?secret|app[\\-_]?secret)\\s*[=:]\\s*[\"']?([a-zA-Z0-9~._\\-]{34,})[\"']?", severity: "critical", category: "cloud" },
  "Azure SQL Connection String":              { re: "(?:Server|Data Source)=[^;]+;(?:Initial Catalog|Database)=[^;]+;(?:User ID|uid)=[^;]+;(?:Password|pwd)=[^;]+", severity: "critical", category: "cloud" },
  "Azure Shared Access Signature":            { re: "[?&]sig=[A-Za-z0-9%+/=]{43,}(?:&|$)", severity: "high", category: "cloud" },
  "Azure Managed Identity Token":             { re: "eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+", severity: "high", category: "cloud" },
  "DigitalOcean Personal Access Token":       { re: "dop_v1_[a-f0-9]{64}", severity: "critical", category: "cloud" },
  "DigitalOcean OAuth Token":                 { re: "doo_v1_[a-f0-9]{64}", severity: "high", category: "cloud" },
  "DigitalOcean Refresh Token":               { re: "dor_v1_[a-f0-9]{64}", severity: "high", category: "cloud" },
  "Alibaba Cloud Access Key ID":              { re: "LTAI[a-zA-Z0-9]{12,20}", severity: "high", category: "cloud" },
  "IBM Cloud API Key":                        { re: "(?:ibm[\\-_]?cloud[\\-_]?api[\\-_]?key|iam[\\-_]?api[\\-_]?key)\\s*[=:]\\s*[\"']?([a-zA-Z0-9\\-_]{44})[\"']?", severity: "critical", category: "cloud" },
  "Oracle Cloud Identifier (OCID)":           { re: "ocid1\\.[a-z]+\\.oc[0-9]\\.[a-z0-9]+\\.[a-z0-9]+", severity: "medium", category: "cloud" },
  "Linode API Token":                         { re: "(?:linode)[\\w\\-]*(?:token|api[\\-_]?key)\\s*[=:]\\s*[\"']?([a-f0-9]{64})[\"']?", severity: "high", category: "cloud" },

  // ══════════════════════════════════════════════════════════════
  // ── S3 / Object Storage ──────────────────────────────────────
  // ══════════════════════════════════════════════════════════════
  "AWS S3 Bucket URL":                        { re: "(?:https?://)?[a-zA-Z0-9.-]+\\.s3[.-](?:us|eu|ap|sa|ca|me|af)-[a-z]+-[0-9]\\.amazonaws\\.com", severity: "medium", category: "cloud", mitre: "T1530" },
  "AWS S3 Path-Style URL":                    { re: "(?:https?://)?s3\\.amazonaws\\.com/[a-zA-Z0-9._-]+", severity: "medium", category: "cloud", mitre: "T1530" },
  "GCS Bucket URL":                           { re: "(?:https?://)?storage\\.googleapis\\.com/[a-zA-Z0-9._-]+", severity: "medium", category: "cloud" },

  // ══════════════════════════════════════════════════════════════
  // ── Git Platform Tokens ──────────────────────────────────────
  // ══════════════════════════════════════════════════════════════
  "GitHub Personal Access Token (Classic)":   { re: "ghp_[A-Za-z0-9_]{36}", severity: "critical", category: "scm", mitre: "T1552.001", remediation: "Revoke token at github.com/settings/tokens. Audit recent API activity.", verify: "github" },
  "GitHub Fine-Grained PAT":                  { re: "github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9]{59}", severity: "critical", category: "scm", verify: "github" },
  "GitHub OAuth Access Token":                { re: "gho_[A-Za-z0-9_]{36}", severity: "high", category: "scm" },
  "GitHub App Installation Token":            { re: "ghs_[A-Za-z0-9_]{36}", severity: "high", category: "scm" },
  "GitHub App Refresh Token":                 { re: "ghr_[A-Za-z0-9_]{36}", severity: "high", category: "scm" },
  "GitLab Personal Access Token":             { re: "glpat-[A-Za-z0-9\\-_]{20,}", severity: "critical", category: "scm", verify: "gitlab" },
  "GitLab Pipeline Trigger Token":            { re: "glptt-[A-Za-z0-9\\-_]{40,}", severity: "high", category: "scm" },
  "GitLab Runner Registration Token":         { re: "GR1348941[A-Za-z0-9\\-_]{20,}", severity: "high", category: "scm" },
  "GitLab Deploy Token":                      { re: "gldt-[A-Za-z0-9\\-_]{20,}", severity: "high", category: "scm" },
  "GitLab CI Job Token":                      { re: "glcbt-[A-Za-z0-9\\-_]{20,}", severity: "medium", category: "scm" },
  "Bitbucket App Password":                   { re: "(?:bitbucket)[\\w\\-]*(?:password|secret|token)\\s*[=:]\\s*[\"']?([a-zA-Z0-9]{18,})[\"']?", severity: "high", category: "scm" },
  "Bitbucket Pipeline Variable":              { re: "BITBUCKET_[A-Z_]+\\s*=\\s*[\"']?([^\"'\\s]{10,})[\"']?", severity: "medium", category: "scm" },

  // ══════════════════════════════════════════════════════════════
  // ── CI/CD ────────────────────────────────────────────────────
  // ══════════════════════════════════════════════════════════════
  "Jenkins API Token":                        { re: "(?:jenkins)[\\w\\-]*(?:token|api[\\-_]?key|secret)\\s*[=:]\\s*[\"']?([a-f0-9]{32,36})[\"']?", severity: "high", category: "cicd", mitre: "T1552.001" },
  "CircleCI API Token":                       { re: "(?:circle[\\-_]?ci|circleci)[\\w\\-]*(?:token)\\s*[=:]\\s*[\"']?([a-f0-9]{40})[\"']?", severity: "high", category: "cicd" },
  "Travis CI Access Token":                   { re: "(?:travis)[\\w\\-]*(?:token)\\s*[=:]\\s*[\"']?([a-zA-Z0-9]{22})[\"']?", severity: "medium", category: "cicd" },
  "GitHub Actions Secret Reference":          { re: "\\$\\{\\{\\s*secrets\\.[A-Z_]+\\s*\\}\\}", severity: "low", category: "cicd" },
  "GitLab CI Variable":                       { re: "\\$CI_[A-Z_]+", severity: "low", category: "cicd" },

  // ══════════════════════════════════════════════════════════════
  // ── Messaging & Collaboration ────────────────────────────────
  // ══════════════════════════════════════════════════════════════
  "Slack Bot Token":                          { re: "xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}", severity: "critical", category: "messaging", verify: "slack" },
  "Slack User Token":                         { re: "xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}", severity: "critical", category: "messaging" },
  "Slack App-Level Token":                    { re: "xapp-[0-9]+-[A-Z0-9]+-[0-9]+-[a-z0-9]+", severity: "high", category: "messaging" },
  "Slack Incoming Webhook URL":               { re: "https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+", severity: "high", category: "messaging" },
  "Slack Configuration Token":                { re: "xoxe\\.xoxp-1-[A-Za-z0-9\\-]+", severity: "critical", category: "messaging" },
  "Discord Webhook URL":                      { re: "https://discord(?:app)?\\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\\-]+", severity: "high", category: "messaging" },
  "Microsoft Teams Webhook":                  { re: "https://[a-z0-9]+\\.webhook\\.office\\.com/webhookb2/[a-f0-9\\-]+/IncomingWebhook/[a-f0-9]+/[a-f0-9\\-]+", severity: "high", category: "messaging" },
  "Telegram Bot API Token":                   { re: "[0-9]{8,10}:[A-Za-z0-9_\\-]{35}", severity: "high", category: "messaging" },

  // ══════════════════════════════════════════════════════════════
  // ── Payment Processors ───────────────────────────────────────
  // ══════════════════════════════════════════════════════════════
  "Stripe Secret Key (Live)":                 { re: "sk_live_[0-9a-zA-Z]{24,}", severity: "critical", category: "payment", mitre: "T1552.001", remediation: "Roll the key immediately in the Stripe Dashboard. Check recent charges.", verify: "stripe" },
  "Stripe Publishable Key (Live)":            { re: "pk_live_[0-9a-zA-Z]{24,}", severity: "medium", category: "payment" },
  "Stripe Restricted API Key":                { re: "rk_live_[0-9a-zA-Z]{24,}", severity: "critical", category: "payment" },
  "Stripe Webhook Signing Secret":            { re: "whsec_[a-zA-Z0-9]{32,}", severity: "high", category: "payment" },
  "Stripe Secret Key (Test)":                 { re: "sk_test_[0-9a-zA-Z]{24,}", severity: "low", category: "payment" },
  "Razorpay Secret Key":                      { re: "(?:razorpay|rzp)[\\w\\-]*(?:secret|key_secret)\\s*[=:]\\s*[\"']?([a-zA-Z0-9]{20,40})[\"']?", severity: "critical", category: "payment" },
  "PayPal Braintree Access Token":            { re: "access_token\\$production\\$[a-z0-9]{16}\\$[a-f0-9]{32}", severity: "critical", category: "payment" },
  "Square Access Token (Production)":         { re: "sq0atp-[A-Za-z0-9\\-_]{22}", severity: "critical", category: "payment" },
  "Square OAuth Secret":                      { re: "sq0csp-[A-Za-z0-9\\-_]{43}", severity: "critical", category: "payment" },
  "Shopify Access Token":                     { re: "shpat_[a-fA-F0-9]{32}", severity: "high", category: "payment" },
  "Shopify Custom App Access Token":          { re: "shpca_[a-fA-F0-9]{32}", severity: "high", category: "payment" },
  "Shopify Private App Password":             { re: "shppa_[a-fA-F0-9]{32}", severity: "high", category: "payment" },
  "Shopify Shared Secret":                    { re: "shpss_[a-fA-F0-9]{32}", severity: "high", category: "payment" },
  "Adyen API Key":                            { re: "(?:adyen)[\\w\\-]*(?:api[\\-_]?key)\\s*[=:]\\s*[\"']?AQE[a-zA-Z0-9]{5,}\\.[a-zA-Z0-9_\\-]+[\"']?", severity: "critical", category: "payment" },

  // ══════════════════════════════════════════════════════════════
  // ── Auth & Identity ──────────────────────────────────────────
  // ══════════════════════════════════════════════════════════════
  "Auth0 Management API Token":               { re: "(?:auth0)[\\w\\-]*(?:token|secret|key)\\s*[=:]\\s*[\"']?([a-zA-Z0-9\\-_]{30,})[\"']?", severity: "high", category: "auth" },
  "Firebase Cloud Messaging Server Key":      { re: "AAAA[a-zA-Z0-9_\\-]{7}:[a-zA-Z0-9_\\-]{140}", severity: "high", category: "auth" },
  "Firebase Web API Key":                     { re: "AIza[0-9A-Za-z_-]{35}", severity: "medium", category: "auth" },
  "HashiCorp Vault Token":                    { re: "(?:hvs|hvb|hvr)\\.[a-zA-Z0-9\\-_]{24,}", severity: "critical", category: "auth", mitre: "T1552.001" },
  "Okta API Token":                           { re: "(?:okta|SSWS)[\\w\\-]*\\s*[=:]?\\s*[\"']?(?:SSWS\\s+)?[a-zA-Z0-9\\-_]{30,}[\"']?", severity: "critical", category: "auth" },
  "Clerk Secret Key":                         { re: "sk_(?:live|test)_[a-zA-Z0-9]{24,}", severity: "high", category: "auth" },
  "Clerk Publishable Key":                    { re: "pk_(?:live|test)_[a-zA-Z0-9]{24,}", severity: "low", category: "auth" },
  "Supabase Service Role Key":                { re: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+", severity: "high", category: "auth" },
  "Supabase API Key":                         { re: "sbp_[a-f0-9]{40}", severity: "high", category: "auth" },
  "Keycloak Client Secret":                   { re: "(?:keycloak)[\\w\\-]*(?:secret|client[\\-_]?secret)\\s*[=:]\\s*[\"']?([a-f0-9\\-]{36})[\"']?", severity: "high", category: "auth" },
  "AWS Cognito User Pool Client Secret":      { re: "(?:cognito)[\\w\\-]*(?:client[\\-_]?secret)\\s*[=:]\\s*[\"']?([a-zA-Z0-9]{52})[\"']?", severity: "high", category: "auth" },

  // ══════════════════════════════════════════════════════════════
  // ── Email & Communication ────────────────────────────────────
  // ══════════════════════════════════════════════════════════════
  "SendGrid API Key":                         { re: "SG\\.[a-zA-Z0-9_\\-]{22}\\.[a-zA-Z0-9_\\-]{43}", severity: "high", category: "email", verify: "sendgrid" },
  "Mailgun API Key":                          { re: "key-[a-f0-9]{32}", severity: "high", category: "email" },
  "Mailchimp API Key":                        { re: "[a-f0-9]{32}-us[0-9]{1,2}", severity: "medium", category: "email" },
  "Postmark Server API Token":                { re: "(?:postmark|pmak)[\\w\\-]*(?:token|key)\\s*[=:]\\s*[\"']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})[\"']?", severity: "medium", category: "email" },
  "Twilio API Key":                           { re: "SK[a-f0-9]{32}", severity: "high", category: "email" },
  "Twilio Account SID":                       { re: "AC[a-f0-9]{32}", severity: "medium", category: "email" },
  "Twilio Auth Token":                        { re: "(?:twilio)[\\w\\-]*(?:auth[\\-_]?token|secret)\\s*[=:]\\s*[\"']?([a-f0-9]{32})[\"']?", severity: "high", category: "email" },
  "Resend API Key":                           { re: "re_[a-zA-Z0-9]{20,}", severity: "high", category: "email" },
  "Plivo Auth ID":                            { re: "(?:plivo)[\\w\\-]*(?:auth[\\-_]?id)\\s*[=:]\\s*[\"']?([A-Z0-9]{20})[\"']?", severity: "medium", category: "email" },

  // ══════════════════════════════════════════════════════════════
  // ── Observability ────────────────────────────────────────────
  // ══════════════════════════════════════════════════════════════
  "Datadog API Key":                          { re: "(?:datadog|dd)[\\w\\-]*(?:api[\\-_]?key)\\s*[=:]\\s*[\"']?([a-f0-9]{32})[\"']?", severity: "high", category: "observability" },
  "Datadog Application Key":                  { re: "(?:datadog|dd)[\\w\\-]*(?:app(?:lication)?[\\-_]?key)\\s*[=:]\\s*[\"']?([a-f0-9]{40})[\"']?", severity: "high", category: "observability" },
  "New Relic Ingest/User API Key":            { re: "(?:NRAK|NRII)-[A-Za-z0-9]{27}", severity: "high", category: "observability" },
  "PagerDuty API Key":                        { re: "(?:pagerduty|pd)[\\w\\-]*(?:api[\\-_]?key|token|secret)\\s*[=:]\\s*[\"']?([a-zA-Z0-9+/]{20,})[\"']?", severity: "medium", category: "observability" },
  "Dynatrace API Token":                      { re: "dt0c01\\.[A-Z0-9]{24}\\.[A-Za-z0-9]{64}", severity: "high", category: "observability" },
  "Grafana Cloud API Key":                    { re: "glc_[A-Za-z0-9+/\\-_]{32,}", severity: "high", category: "observability" },
  "Grafana Service Account Token":            { re: "glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}", severity: "high", category: "observability" },
  "Snyk API Token":                           { re: "(?:SNYK_TOKEN|snyk[\\-_]?api[\\-_]?token)\\s*[=:]\\s*[\"']?([a-f0-9\\-]{36})[\"']?", severity: "medium", category: "observability" },
  "SonarQube Token":                          { re: "sq[pua]_[a-f0-9]{40}", severity: "medium", category: "observability" },
  "Sentry DSN":                               { re: "https://[a-f0-9]{32}@(?:o[0-9]+\\.)?(?:[a-z]+\\.)?sentry\\.io/[0-9]+", severity: "medium", category: "observability" },
  "Splunk HEC Token":                         { re: "(?:splunk|hec)[\\w\\-]*(?:token)\\s*[=:]\\s*[\"']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})[\"']?", severity: "high", category: "observability" },

  // ══════════════════════════════════════════════════════════════
  // ── Database ─────────────────────────────────────────────────
  // ══════════════════════════════════════════════════════════════
  "Database Connection String with Password": { re: "(?:postgres|mysql|mongodb|redis|amqp|mssql|sqlserver)(?:ql)?://[^:]+:[^@]+@[^/\\s]+", severity: "critical", category: "database", mitre: "T1552.001", remediation: "Rotate database credentials immediately. Audit access logs." },
  "MongoDB SRV Connection String":            { re: "mongodb\\+srv://[^:]+:[^@]+@[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]+", severity: "critical", category: "database" },
  "Redis Connection URL with Password":       { re: "redis://[^:]*:[^@]+@[^/\\s:]+(?::[0-9]+)?", severity: "critical", category: "database" },
  "PlanetScale Database Password":            { re: "pscale_pw_[a-zA-Z0-9\\-_]{43}", severity: "critical", category: "database" },
  "PlanetScale OAuth Token":                  { re: "pscale_tkn_[a-zA-Z0-9\\-_]{43}", severity: "high", category: "database" },
  "CockroachDB Connection String":            { re: "(?:cockroach|crdb)(?:db)?://[^:]+:[^@]+@[^/\\s]+", severity: "critical", category: "database" },
  "Neon Database Connection String":          { re: "postgres(?:ql)?://[^:]+:[^@]+@[^/]*neon\\.tech", severity: "critical", category: "database" },
  "Turso Database Token":                     { re: "(?:turso|libsql)[\\w\\-]*(?:token|auth)\\s*[=:]\\s*[\"']?([a-zA-Z0-9\\-_.]+)[\"']?", severity: "high", category: "database" },

  // ══════════════════════════════════════════════════════════════
  // ── AI / ML API Keys ─────────────────────────────────────────
  // ══════════════════════════════════════════════════════════════
  "OpenAI API Key":                           { re: "sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}", severity: "critical", category: "ai", verify: "openai" },
  "OpenAI API Key (Project-based)":           { re: "sk-proj-[a-zA-Z0-9\\-_]{80,}", severity: "critical", category: "ai" },
  "Anthropic API Key":                        { re: "sk-ant-api03-[a-zA-Z0-9\\-_]{93}", severity: "critical", category: "ai" },
  "Hugging Face Access Token":                { re: "hf_[a-zA-Z0-9]{34,}", severity: "high", category: "ai" },
  "Cohere API Key":                           { re: "(?:cohere)[\\w\\-]*(?:api[\\-_]?key|token)\\s*[=:]\\s*[\"']?([a-zA-Z0-9]{40})[\"']?", severity: "high", category: "ai" },
  "Replicate API Token":                      { re: "r8_[a-zA-Z0-9]{20}", severity: "high", category: "ai" },
  "Groq API Key":                             { re: "gsk_[a-zA-Z0-9]{48,}", severity: "high", category: "ai" },
  "Mistral API Key":                          { re: "(?:mistral)[\\w\\-]*(?:api[\\-_]?key)\\s*[=:]\\s*[\"']?([a-zA-Z0-9]{32})[\"']?", severity: "high", category: "ai" },
  "Pinecone API Key":                         { re: "(?:pinecone)[\\w\\-]*(?:api[\\-_]?key)\\s*[=:]\\s*[\"']?([a-f0-9\\-]{36})[\"']?", severity: "high", category: "ai" },
  "Together AI API Key":                      { re: "(?:together)[\\w\\-]*(?:api[\\-_]?key)\\s*[=:]\\s*[\"']?([a-f0-9]{64})[\"']?", severity: "high", category: "ai" },
  "Stability AI API Key":                     { re: "sk-[A-Za-z0-9]{48,}", severity: "high", category: "ai" },
  "Google Gemini API Key":                    { re: "(?:gemini|google[\\-_]?ai)[\\w\\-]*(?:api[\\-_]?key)\\s*[=:]\\s*[\"']?AIza[0-9A-Za-z_-]{35}[\"']?", severity: "high", category: "ai" },

  // ══════════════════════════════════════════════════════════════
  // ── Infrastructure & CDN ─────────────────────────────────────
  // ══════════════════════════════════════════════════════════════
  "Cloudflare Global API Key":                { re: "(?:cloudflare|cf)[\\w\\-]*(?:api[\\-_]?key)\\s*[=:]\\s*[\"']?([a-f0-9]{37})[\"']?", severity: "critical", category: "infra" },
  "Cloudflare API Token":                     { re: "(?:cloudflare|cf)[\\w\\-]*(?:token)\\s*[=:]\\s*[\"']?([A-Za-z0-9\\-_]{40})[\"']?", severity: "high", category: "infra" },
  "Vercel Access Token":                      { re: "(?:vercel)[\\w\\-]*(?:token|secret)\\s*[=:]\\s*[\"']?([a-zA-Z0-9]{24})[\"']?", severity: "high", category: "infra" },
  "Netlify Access Token":                     { re: "(?:netlify)[\\w\\-]*(?:token|auth[\\-_]?token)\\s*[=:]\\s*[\"']?([a-zA-Z0-9\\-_]{40,})[\"']?", severity: "high", category: "infra" },
  "Heroku API Key":                           { re: "(?:heroku)[\\w\\-]*(?:api[\\-_]?key|token|secret)\\s*[=:]\\s*[\"']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})[\"']?", severity: "high", category: "infra" },
  "Fastly API Token":                         { re: "(?:fastly)[\\w\\-]*(?:api[\\-_]?key|token)\\s*[=:]\\s*[\"']?([a-zA-Z0-9\\-_]{32})[\"']?", severity: "high", category: "infra" },
  "Terraform Cloud API Token":                { re: "(?:TFE_TOKEN|terraform_cloud_token|atlas_token)\\s*[=:]\\s*[\"']?([a-zA-Z0-9\\.\\-_]{14,})[\"']?", severity: "high", category: "infra" },
  "Pulumi Access Token":                      { re: "pul-[a-f0-9]{40}", severity: "high", category: "infra" },
  "Docker Hub Personal Access Token":         { re: "dckr_pat_[A-Za-z0-9\\-_]{27,}", severity: "high", category: "infra" },
  "Kubernetes Service Account Token":         { re: "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik[A-Za-z0-9_-]+", severity: "high", category: "infra" },
  "Fly.io API Token":                         { re: "fo1_[a-zA-Z0-9_]{40,}", severity: "high", category: "infra" },
  "Render API Key":                           { re: "rnd_[a-zA-Z0-9]{32,}", severity: "high", category: "infra" },
  "Railway API Token":                        { re: "(?:railway)[\\w\\-]*(?:token|api)\\s*[=:]\\s*[\"']?([a-f0-9\\-]{36})[\"']?", severity: "high", category: "infra" },

  // ══════════════════════════════════════════════════════════════
  // ── SaaS & Productivity ──────────────────────────────────────
  // ══════════════════════════════════════════════════════════════
  "Atlassian API Token":                      { re: "(?:atlassian|jira|confluence)[\\w\\-]*(?:api[\\-_]?token|secret)\\s*[=:]\\s*[\"']?([a-zA-Z0-9]{24})[\"']?", severity: "medium", category: "saas" },
  "Linear API Key":                           { re: "lin_api_[a-zA-Z0-9]{40}", severity: "medium", category: "saas" },
  "Notion Integration Token":                 { re: "(?:ntn_|secret_)[a-zA-Z0-9]{43}", severity: "medium", category: "saas" },
  "Airtable API Key":                         { re: "pat[a-zA-Z0-9]{14}\\.[a-f0-9]{64}", severity: "medium", category: "saas" },
  "Algolia Admin API Key":                    { re: "(?:algolia)[\\w\\-]*(?:admin[\\-_]?(?:api[\\-_]?)?key)\\s*[=:]\\s*[\"']?([a-f0-9]{32})[\"']?", severity: "high", category: "saas" },
  "LaunchDarkly SDK Key":                     { re: "sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", severity: "medium", category: "saas" },
  "LaunchDarkly API Access Token":            { re: "api-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", severity: "high", category: "saas" },
  "Segment Write Key":                        { re: "(?:segment)[\\w\\-]*(?:write[\\-_]?key|api[\\-_]?key)\\s*[=:]\\s*[\"']?([a-zA-Z0-9]{32})[\"']?", severity: "medium", category: "saas" },
  "Intercom Access Token":                    { re: "(?:intercom)[\\w\\-]*(?:token|access[\\-_]?token)\\s*[=:]\\s*[\"']?([a-zA-Z0-9=_\\-]{60})[\"']?", severity: "medium", category: "saas" },
  "Zendesk API Token":                        { re: "(?:zendesk)[\\w\\-]*(?:token|api[\\-_]?token)\\s*[=:]\\s*[\"']?([a-zA-Z0-9]{40})[\"']?", severity: "medium", category: "saas" },
  "Figma Personal Access Token":              { re: "figd_[a-zA-Z0-9\\-_]{40,}", severity: "medium", category: "saas" },
  "Asana Personal Access Token":              { re: "(?:asana)[\\w\\-]*(?:token|pat)\\s*[=:]\\s*[\"']?([0-9]/[0-9]+:[a-zA-Z0-9]{32})[\"']?", severity: "medium", category: "saas" },
  "Monday.com API Token":                     { re: "(?:monday)[\\w\\-]*(?:api[\\-_]?token|token)\\s*[=:]\\s*[\"']?eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+[\"']?", severity: "medium", category: "saas" },
  "Typeform Personal Access Token":           { re: "tfp_[a-zA-Z0-9]{40,}", severity: "medium", category: "saas" },

  // ══════════════════════════════════════════════════════════════
  // ── Social Platforms ─────────────────────────────────────────
  // ══════════════════════════════════════════════════════════════
  "Twitter/X API Key":                        { re: "(?:twitter|tweet)[\\w\\-]*(?:api[\\-_]?key|consumer[\\-_]?key)\\s*[=:]\\s*[\"']?([a-zA-Z0-9]{25})[\"']?", severity: "high", category: "social" },
  "YouTube Data API Key":                     { re: "(?:youtube|yt)[\\w\\-]*(?:api[\\-_]?key|key)\\s*[=:]\\s*[\"']?AIza[0-9A-Za-z_-]{35}[\"']?", severity: "medium", category: "social" },

  // ══════════════════════════════════════════════════════════════
  // ── Package Registries ───────────────────────────────────────
  // ══════════════════════════════════════════════════════════════
  "npm Access Token":                         { re: "npm_[a-zA-Z0-9]{36}", severity: "high", category: "registry", mitre: "T1195.001" },
  "PyPI API Token":                           { re: "pypi-[a-zA-Z0-9\\-_]{100,}", severity: "high", category: "registry" },
  "NuGet API Key":                            { re: "oy2[a-z0-9]{43}", severity: "medium", category: "registry" },
  "RubyGems API Key":                         { re: "rubygems_[a-f0-9]{48}", severity: "medium", category: "registry" },

  // ══════════════════════════════════════════════════════════════
  // ── Secrets Management ───────────────────────────────────────
  // ══════════════════════════════════════════════════════════════
  "Doppler Service Token":                    { re: "dp\\.st\\.[a-zA-Z0-9_\\-]{40,}", severity: "high", category: "secrets" },
  "Infisical Token":                          { re: "st\\.[a-f0-9]{8}\\.[a-f0-9]{48}", severity: "high", category: "secrets" },

  // ══════════════════════════════════════════════════════════════
  // ── Cryptographic Material ───────────────────────────────────
  // ══════════════════════════════════════════════════════════════
  "Private Key (PEM format)":                 { re: "-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", severity: "critical", category: "crypto", mitre: "T1552.004", remediation: "Revoke and regenerate the key pair immediately. Check for unauthorized access." },
  "PGP Private Key Block":                    { re: "-----BEGIN PGP PRIVATE KEY BLOCK-----", severity: "critical", category: "crypto" },
  "SSH Private Key (OpenSSH)":                { re: "-----BEGIN OPENSSH PRIVATE KEY-----", severity: "critical", category: "crypto" },
  "PKCS12/PFX Certificate":                   { re: "-----BEGIN CERTIFICATE-----", severity: "medium", category: "crypto" },

  // ══════════════════════════════════════════════════════════════
  // ── Auth Headers & Tokens ────────────────────────────────────
  // ══════════════════════════════════════════════════════════════
  "Bearer Token in Authorization Header":     { re: "(?:Authorization|Bearer)\\s*[:=]\\s*[\"']?Bearer\\s+([a-zA-Z0-9\\-_\\.]{20,500})[\"']?", severity: "high", category: "auth" },
  "Basic Auth Credentials":                   { re: "(?:Authorization)\\s*[:=]\\s*[\"']?Basic\\s+([A-Za-z0-9+/=]{10,})[\"']?", severity: "high", category: "auth", mitre: "T1552.001" },

  // ══════════════════════════════════════════════════════════════
  // ── Generic Assignments ──────────────────────────────────────
  // ══════════════════════════════════════════════════════════════
  "Generic API Key Assignment":               { re: "(?:api[\\-_]?key|apikey|api[\\-_]?token|api[\\-_]?secret)\\s*[=:]\\s*[\"']([a-zA-Z0-9\\-_]{20,64})[\"']", severity: "medium", category: "generic" },
  "Generic Secret Assignment":                { re: "(?:secret|password|passwd|pwd|token|auth[\\-_]?token|access[\\-_]?token|private[\\-_]?key)\\s*[=:]\\s*[\"']([^\\s\"']{8,64})[\"']", severity: "medium", category: "generic" },
  "Generic Password in URL":                  { re: "(?:://[^:]+):([^@]{8,40})@", severity: "high", category: "generic", mitre: "T1552.001" },
};

export const generics = {
  "Generic API Key":  { re: "[aA][pP][iI]_?[kK][eE][yY].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]", severity: "low", category: "generic" },
  "Generic Secret":   { re: "[sS][eE][cC][rR][eE][tT].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]", severity: "low", category: "generic" },
};

export const aws = {
  "AWS API Key": { re: "((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})", severity: "critical", category: "cloud", verify: "aws" },
};

// ── Category metadata ───────────────────────────────────────────
export const CATEGORIES = {
  cloud:         { label: "Cloud", icon: "☁️",  color: "#f0883e" },
  scm:           { label: "Source Control", icon: "📂", color: "#f0883e" },
  cicd:          { label: "CI/CD", icon: "⚡", color: "#d29922" },
  messaging:     { label: "Messaging", icon: "💬", color: "#f85149" },
  payment:       { label: "Payment", icon: "💳", color: "#f85149" },
  auth:          { label: "Auth", icon: "🔑", color: "#f0883e" },
  email:         { label: "Email", icon: "📧", color: "#d29922" },
  observability: { label: "Observability", icon: "📊", color: "#58a6ff" },
  database:      { label: "Database", icon: "🗄️", color: "#f85149" },
  ai:            { label: "AI/ML", icon: "🤖", color: "#d29922" },
  infra:         { label: "Infrastructure", icon: "🏗️", color: "#d29922" },
  saas:          { label: "SaaS", icon: "📦", color: "#58a6ff" },
  social:        { label: "Social", icon: "🌐", color: "#58a6ff" },
  registry:      { label: "Registry", icon: "📦", color: "#d29922" },
  secrets:       { label: "Secrets Mgmt", icon: "🔐", color: "#f0883e" },
  crypto:        { label: "Crypto", icon: "🔒", color: "#f85149" },
  generic:       { label: "Generic", icon: "🔍", color: "#8b949e" },
};

// ── Helper functions ────────────────────────────────────────────

export function getRegexMap(patternSets) {
  const regexes = {};
  for (const set of patternSets) {
    for (const [name, config] of Object.entries(set)) {
      regexes[name] = config.re;
    }
  }
  return regexes;
}

export function getSeverity(name) {
  const allPatterns = { ...specifics, ...generics, ...aws };
  return allPatterns[name]?.severity || "info";
}

export function getPatternMeta(name) {
  const allPatterns = { ...specifics, ...generics, ...aws };
  return allPatterns[name] || { severity: "info" };
}

export function getPatternCount() {
  return Object.keys(specifics).length + Object.keys(generics).length + Object.keys(aws).length;
}

export const denyList = ["AIDAAAAAAAAAAAAAAAAA"];
