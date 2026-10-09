variable "pingfederate_https_host" {
  description = "The PingFederate admin node's address (https://host:port)"
  type        = string
}

variable "pingfederate_create_key_pairs" {
  description = "Import the key pairs into PingFederate (false where it already holds them: the provider can't adopt key pairs)"
  type        = bool
  default     = true
}

variable "pf_signing_key" {
  description = "the secret of role pf-signing-key (azkv://kv-ciam-prod/pf-signing-key), supplied at apply time"
  type        = string
  sensitive   = true
}

variable "pf_signing_key_password" {
  description = "the secret of role pf-signing-key-password (azkv://kv-ciam-prod/pf-signing-key-password), supplied at apply time"
  type        = string
  sensitive   = true
}

variable "sso_tls_keystore" {
  description = "the secret of role sso-tls-keystore (azkv://kv-ciam-prod/sso-tls-keystore), supplied at apply time"
  type        = string
  sensitive   = true
}

variable "sso_tls_keystore_password" {
  description = "the secret of role sso-tls-keystore-password (azkv://kv-ciam-prod/sso-tls-keystore-password), supplied at apply time"
  type        = string
  sensitive   = true
}

variable "pf_corp_ad_bind_password" {
  description = "the secret of role pf-corp-ad-bind-password (azkv://kv-ciam-prod/pf-corp-ad-bind-password), supplied at apply time"
  type        = string
  sensitive   = true
}

variable "pf_grants_db_password" {
  description = "the secret of role pf-grants-db-password (azkv://kv-ciam-prod/pf-grants-db-password), supplied at apply time"
  type        = string
  sensitive   = true
}

variable "pf_ds_bind_password" {
  description = "the secret of role pf-ds-bind-password (azkv://kv-ciam-prod/pf-ds-bind-password), supplied at apply time"
  type        = string
  sensitive   = true
}

variable "pf_smtp_password" {
  description = "the secret of role pf-smtp-password (azkv://kv-ciam-prod/pf-smtp-password), supplied at apply time"
  type        = string
  sensitive   = true
}

variable "pf_captcha_secret" {
  description = "the secret of role pf-captcha-secret (azkv://kv-ciam-prod/pf-captcha-secret), supplied at apply time"
  type        = string
  sensitive   = true
}

variable "reports_api_withheld" {
  description = "a secret of reports_api no credential role supplies yet (set pingfedCredentialRole)"
  type        = string
  sensitive   = true
}
