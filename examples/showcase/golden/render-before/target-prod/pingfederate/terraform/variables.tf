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

variable "corp_directory_withheld" {
  description = "a secret of corp_directory no credential role supplies yet (set pingfedCredentialRole)"
  type        = string
  sensitive   = true
}

variable "grant_store_withheld" {
  description = "a secret of grant_store no credential role supplies yet (set pingfedCredentialRole)"
  type        = string
  sensitive   = true
}

variable "user_directory_withheld" {
  description = "a secret of user_directory no credential role supplies yet (set pingfedCredentialRole)"
  type        = string
  sensitive   = true
}

variable "smtp_withheld" {
  description = "a secret of smtp no credential role supplies yet (set pingfedCredentialRole)"
  type        = string
  sensitive   = true
}

variable "recaptcha_withheld" {
  description = "a secret of recaptcha no credential role supplies yet (set pingfedCredentialRole)"
  type        = string
  sensitive   = true
}

variable "reports_api_withheld" {
  description = "a secret of reports_api no credential role supplies yet (set pingfedCredentialRole)"
  type        = string
  sensitive   = true
}
