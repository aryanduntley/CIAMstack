resource "pingfederate_keypairs_signing_key" "signing_2025" {
  count     = var.pingfederate_create_key_pairs ? 1 : 0
  key_id    = "signing-2025"
  file_data = var.pf_signing_key
  format    = "PKCS12"
  password  = var.pf_signing_key_password
}

resource "pingfederate_keypairs_ssl_server_key" "sso_tls_2026" {
  count      = var.pingfederate_create_key_pairs ? 1 : 0
  key_id     = "sso-tls-2026"
  file_data  = var.sso_tls_keystore
  format     = "PKCS12"
  password   = var.sso_tls_keystore_password
  depends_on = [pingfederate_keypairs_signing_key.signing_2025]
}

resource "pingfederate_data_store" "corp_directory" {
  data_store_id = "corp-directory"
  ldap_data_store = {
    hostnames       = ["dc1.corp.example-aero.test:636", "dc2.corp.example-aero.test:636"]
    ldap_type       = "ACTIVE_DIRECTORY"
    max_connections = 20
    min_connections = 2
    name            = "Corporate directory"
    password        = var.corp_directory_withheld
    use_ssl         = true
    user_dn         = "CN=svc-pingfed,OU=Service Accounts,DC=corp,DC=example-aero,DC=test"
  }
  depends_on = [pingfederate_keypairs_ssl_server_key.sso_tls_2026]
}

resource "pingfederate_data_store" "grant_store" {
  data_store_id = "grant-store"
  jdbc_data_store = {
    connection_url = "jdbc:postgresql://psql-ciam-prod-pf-grants.postgres.database.azure.com:5432/pf"
    driver_class   = "org.postgresql.Driver"
    name           = "Persistent grant store"
    password       = var.grant_store_withheld
    user_name      = "pf_grants"
  }
  depends_on = [pingfederate_keypairs_ssl_server_key.sso_tls_2026]
}

resource "pingfederate_data_store" "user_directory" {
  data_store_id = "user-directory"
  ldap_data_store = {
    hostnames       = ["ldap.id.example-aero.test:1636", "ds-1.aws.internal.example-aero.test:1636"]
    ldap_type       = "PING_DIRECTORY"
    max_connections = 100
    min_connections = 10
    name            = "User directory"
    password        = var.user_directory_withheld
    use_ssl         = true
    user_dn         = "uid=pf-svc,ou=service-accounts,dc=partners,dc=example-aero,dc=test"
  }
  depends_on = [pingfederate_keypairs_ssl_server_key.sso_tls_2026]
}

resource "pingfederate_password_credential_validator" "pcvcustomers" {
  validator_id = "pcvcustomers"
  plugin_descriptor_ref = {
    id = "org.sourceid.saml20.domain.LDAPUsernamePasswordCredentialValidator"
  }
  attribute_contract = {}
  configuration = {
    tables = []
    fields = [
      {
        name  = "LDAP Datastore"
        value = "user-directory"
      },
      {
        name  = "Search Base"
        value = "ou=people,dc=partners,dc=example-aero,dc=test"
      },
      {
        name  = "Search Filter"
        value = "uid=$${username}"
      },
    ]
  }
  name       = "Customer directory"
  depends_on = [pingfederate_data_store.corp_directory, pingfederate_data_store.grant_store, pingfederate_data_store.user_directory]
}

resource "pingfederate_notification_publisher" "smtp" {
  publisher_id = "smtp"
  plugin_descriptor_ref = {
    id = "com.pingidentity.email.SmtpNotificationPlugin"
  }
  configuration = {
    fields = [
      {
        name  = "From Address"
        value = "noreply@example-aero.test"
      },
      {
        name  = "Email Server"
        value = "email-smtp.us-east-1.amazonaws.com"
      },
      {
        name  = "SMTP Port"
        value = "587"
      },
      {
        name  = "Encryption Method"
        value = "TLS"
      },
      {
        name  = "Username"
        value = "AKIAEXAMPLESMTPUSER"
      },
    ]
    sensitive_fields = [
      {
        name  = "Password"
        value = var.smtp_withheld
      },
    ]
  }
  name       = "SES SMTP"
  depends_on = [pingfederate_password_credential_validator.pcvcustomers]
}

resource "pingfederate_captcha_provider" "recaptcha" {
  provider_id = "recaptcha"
  plugin_descriptor_ref = {
    id = "com.pingidentity.captcha.recaptchav3.ReCaptchaV3Plugin"
  }
  configuration = {
    fields = [
      {
        name  = "Site Key"
        value = "6LcEXAMPLEsyntheticSiteKey000000000000"
      },
      {
        name  = "Pass Score Threshold"
        value = "0.5"
      },
    ]
    sensitive_fields = [
      {
        name  = "Secret Key"
        value = var.recaptcha_withheld
      },
    ]
  }
  name       = "reCAPTCHA v3"
  depends_on = [pingfederate_notification_publisher.smtp]
}

resource "pingfederate_idp_adapter" "htmlform" {
  adapter_id = "htmlform"
  plugin_descriptor_ref = {
    id = "com.pingidentity.adapters.htmlform.idp.HtmlFormIdpAuthnAdapter"
  }
  attribute_contract = {
    core_attributes = [
      {
        name      = "username"
        pseudonym = true
      },
    ]
    extended_attributes = [
      {
        name = "mail"
      },
    ]
  }
  attribute_mapping = {
    attribute_contract_fulfillment = {
      mail = {
        source = {
          type = "ADAPTER"
        }
        value = "mail"
      }
      username = {
        source = {
          type = "ADAPTER"
        }
        value = "username"
      }
    }
    attribute_sources = []
    issuance_criteria = {
      conditional_criteria = []
    }
  }
  configuration = {
    tables = [
      {
        name = "Credential Validators"
        rows = [
          {
            default_row = false
            fields = [
              {
                name  = "Password Credential Validator Instance"
                value = "pcvcustomers"
              },
            ]
          },
        ]
      },
    ]
    fields = [
      {
        name  = "Login Template"
        value = "html.form.login.template.html"
      },
      {
        name  = "Allow Password Changes"
        value = "false"
      },
    ]
  }
  name       = "HTML Form"
  depends_on = [pingfederate_captcha_provider.recaptcha]
}

resource "pingfederate_oauth_access_token_manager" "defaultjwt" {
  manager_id = "defaultjwt"
  plugin_descriptor_ref = {
    id = "com.pingidentity.pf.access.token.management.plugins.JwtBearerAccessTokenManagementPlugin"
  }
  attribute_contract = {
    extended_attributes = [
      {
        name = "sub"
      },
      {
        name = "scope"
      },
    ]
  }
  configuration = {
    tables = [
      {
        name = "Symmetric Keys"
        rows = []
      },
      {
        name = "Certificates"
        rows = [
          {
            default_row = true
            fields = [
              {
                name  = "Key ID"
                value = "k1"
              },
              {
                name  = "Certificate"
                value = "signing-2025"
              },
            ]
          },
        ]
      },
    ]
    fields = [
      {
        name  = "Token Lifetime"
        value = "120"
      },
      {
        name  = "JWS Algorithm"
        value = "RS256"
      },
      {
        name  = "Active Signing Certificate Key ID"
        value = "k1"
      },
    ]
  }
  name       = "Default JWT"
  depends_on = [pingfederate_idp_adapter.htmlform]
}

resource "pingfederate_authentication_policy_contract" "default_apc" {
  contract_id = "default-apc"
  extended_attributes = [
    {
      name = "mail"
    },
  ]
  name       = "Default"
  depends_on = [pingfederate_oauth_access_token_manager.defaultjwt]
}

resource "pingfederate_authentication_policies" "authenticationpolicies_default" {
  fail_if_no_selection    = false
  tracked_http_parameters = []
  authn_selection_trees = [
    {
      name    = "Customers"
      enabled = true
      root_node = {
        action = {
          authn_source_policy_action = {
            authentication_source = {
              source_ref = {
                id = "htmlform"
              }
              type = "IDP_ADAPTER"
            }
          }
        }
        children = [
          {
            action = {
              apc_mapping_policy_action = {
                attribute_mapping = {
                  attribute_contract_fulfillment = {
                    mail = {
                      source = {
                        id   = "htmlform"
                        type = "ADAPTER"
                      }
                      value = "mail"
                    }
                    subject = {
                      source = {
                        id   = "htmlform"
                        type = "ADAPTER"
                      }
                      value = "username"
                    }
                  }
                }
                authentication_policy_contract_ref = {
                  id = "default-apc"
                }
                context = "Success"
              }
            }
          },
          {
            action = {
              done_policy_action = {
                context = "Fail"
              }
            }
          },
        ]
      }
    },
  ]
  depends_on = [pingfederate_authentication_policy_contract.default_apc]
}

resource "pingfederate_openid_connect_policy" "default_oidc" {
  policy_id = "default-oidc"
  access_token_manager_ref = {
    id = "defaultjwt"
  }
  attribute_contract = {
    extended_attributes = [
      {
        name = "email"
      },
    ]
  }
  attribute_mapping = {
    attribute_contract_fulfillment = {
      email = {
        source = {
          type = "TOKEN"
        }
        value = "mail"
      }
      sub = {
        source = {
          type = "TOKEN"
        }
        value = "sub"
      }
    }
  }
  id_token_lifetime = 5
  name              = "Default"
  depends_on        = [pingfederate_authentication_policies.authenticationpolicies_default]
}

resource "pingfederate_oauth_server_settings" "oauth_authserversettings" {
  authorization_code_entropy = 30
  authorization_code_timeout = 60
  exclusive_scopes           = []
  persistent_grant_lifetime  = -1
  refresh_rolling_interval   = 0
  refresh_token_length       = 42
  scopes = [
    {
      description = "Email address"
      name        = "email"
    },
    {
      description = "Basic profile"
      name        = "profile"
    },
    {
      description = "Refresh tokens"
      name        = "offline_access"
    },
    {
      description = "Read MRO reports"
      name        = "reports.read"
    },
  ]
  depends_on = [pingfederate_openid_connect_policy.default_oidc]
}

resource "pingfederate_oauth_client" "mobile_ops" {
  client_auth = {
    type = "NONE"
  }
  client_id = "mobile-ops"
  default_access_token_manager_ref = {
    id = "defaultjwt"
  }
  enabled     = true
  grant_types = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  name        = "mobile-ops"
  oidc_policy = {
    policy_group = {
      id = "default-oidc"
    }
  }
  redirect_uris                       = ["https://mobile.example-aero.test/oauth2/callback"]
  require_proof_key_for_code_exchange = true
  restrict_scopes                     = true
  restricted_scopes                   = ["openid", "email", "offline_access"]
  depends_on                          = [pingfederate_oauth_server_settings.oauth_authserversettings]
}

resource "pingfederate_oauth_client" "reports_api" {
  client_auth = {
    secret = var.reports_api_withheld
    type   = "SECRET"
  }
  client_id = "reports-api"
  default_access_token_manager_ref = {
    id = "defaultjwt"
  }
  enabled           = true
  grant_types       = ["CLIENT_CREDENTIALS"]
  name              = "Reporting API"
  restrict_scopes   = true
  restricted_scopes = ["reports.read"]
  depends_on        = [pingfederate_oauth_server_settings.oauth_authserversettings]
}

resource "pingfederate_oauth_client" "tech_pubs_web" {
  client_auth = {
    type = "NONE"
  }
  client_id = "tech-pubs-web"
  default_access_token_manager_ref = {
    id = "defaultjwt"
  }
  enabled                             = true
  grant_types                         = ["AUTHORIZATION_CODE", "REFRESH_TOKEN"]
  name                                = "tech-pubs"
  redirect_uris                       = ["https://techpubs.example-aero.test/oidc/callback"]
  require_proof_key_for_code_exchange = true
  restrict_scopes                     = true
  restricted_scopes                   = ["openid", "profile", "email"]
  depends_on                          = [pingfederate_oauth_server_settings.oauth_authserversettings]
}

resource "pingfederate_idp_sp_connection" "customer_portal" {
  connection_id = "customer-portal"
  active        = true
  contact_info = {
    company = "customer-portal-team"
  }
  credentials = {
    certs = [
      {
        primary_verification_cert = true
        x509_file = {
          file_data = "-----BEGIN CERTIFICATE-----\nU1lOVEhFVElDIENFUlRJRklDQVRFIENOPXBvcnRhbC5leGFtcGxlLWFlcm8udGVzdCBTUA==\n-----END CERTIFICATE-----\n"
        }
      },
    ]
    signing_settings = {
      algorithm = "SHA256withRSA"
      signing_key_pair_ref = {
        id = "signing-2025"
      }
    }
  }
  entity_id = "https://portal.example-aero.test/saml/sp"
  name      = "customer-portal"
  sp_browser_sso = {
    adapter_mappings = [
      {
        attribute_contract_fulfillment = {
          SAML_SUBJECT = {
            source = {
              id   = "user-directory"
              type = "LDAP_DATA_STORE"
            }
            value = "uid"
          }
          company = {
            source = {
              id   = "user-directory"
              type = "LDAP_DATA_STORE"
            }
            value = "companyId"
          }
          email = {
            source = {
              id   = "user-directory"
              type = "LDAP_DATA_STORE"
            }
            value = "mail"
          }
          family_name = {
            source = {
              id   = "user-directory"
              type = "LDAP_DATA_STORE"
            }
            value = "sn"
          }
          given_name = {
            source = {
              id   = "user-directory"
              type = "LDAP_DATA_STORE"
            }
            value = "givenName"
          }
          roles = {
            source = {
              id   = "user-directory"
              type = "LDAP_DATA_STORE"
            }
            value = "appEntitlement"
          }
        }
        idp_adapter_ref = {
          id = "htmlform"
        }
      },
    ]
    assertion_lifetime = {
      minutes_after  = 5
      minutes_before = 5
    }
    attribute_contract = {
      core_attributes = [
        {
          name = "SAML_SUBJECT"
        },
      ]
      extended_attributes = [
        {
          name = "company"
        },
        {
          name = "email"
        },
        {
          name = "family_name"
        },
        {
          name = "given_name"
        },
        {
          name = "roles"
        },
      ]
    }
    enabled_profiles = ["SP_INITIATED_SSO"]
    protocol         = "SAML20"
    sso_service_endpoints = [
      {
        binding    = "POST"
        is_default = true
        url        = "https://portal.example-aero.test/saml/acs"
      },
    ]
  }
  depends_on = [pingfederate_oauth_client.mobile_ops, pingfederate_oauth_client.reports_api, pingfederate_oauth_client.tech_pubs_web]
}

resource "pingfederate_idp_sp_connection" "supplier_portal" {
  connection_id = "supplier-portal"
  active        = true
  contact_info = {
    company = "supplier-portal-team"
  }
  credentials = {
    certs = [
      {
        primary_verification_cert = true
        x509_file = {
          file_data = "-----BEGIN CERTIFICATE-----\nU1lOVEhFVElDIENFUlRJRklDQVRFIENOPXN1cHBsaWVycy5leGFtcGxlLWFlcm8udGVzdCBTUA==\n-----END CERTIFICATE-----\n"
        }
      },
    ]
    signing_settings = {
      algorithm = "SHA256withRSA"
      signing_key_pair_ref = {
        id = "signing-2025"
      }
    }
  }
  entity_id = "https://suppliers.example-aero.test/saml/sp"
  name      = "supplier-portal"
  sp_browser_sso = {
    adapter_mappings = [
      {
        attribute_contract_fulfillment = {
          SAML_SUBJECT = {
            source = {
              id   = "user-directory"
              type = "LDAP_DATA_STORE"
            }
            value = "uid"
          }
          company = {
            source = {
              id   = "user-directory"
              type = "LDAP_DATA_STORE"
            }
            value = "companyId"
          }
          email = {
            source = {
              id   = "user-directory"
              type = "LDAP_DATA_STORE"
            }
            value = "mail"
          }
          roles = {
            source = {
              id   = "user-directory"
              type = "LDAP_DATA_STORE"
            }
            value = "appEntitlement"
          }
          sold_to = {
            source = {
              id   = "user-directory"
              type = "LDAP_DATA_STORE"
            }
            value = "soldToAccount"
          }
        }
        idp_adapter_ref = {
          id = "htmlform"
        }
      },
    ]
    assertion_lifetime = {
      minutes_after  = 5
      minutes_before = 5
    }
    attribute_contract = {
      core_attributes = [
        {
          name = "SAML_SUBJECT"
        },
      ]
      extended_attributes = [
        {
          name = "company"
        },
        {
          name = "email"
        },
        {
          name = "roles"
        },
        {
          name = "sold_to"
        },
      ]
    }
    enabled_profiles = ["SP_INITIATED_SSO"]
    protocol         = "SAML20"
    sso_service_endpoints = [
      {
        binding    = "POST"
        is_default = true
        url        = "https://suppliers.example-aero.test/saml/acs"
      },
    ]
  }
  depends_on = [pingfederate_oauth_client.mobile_ops, pingfederate_oauth_client.reports_api, pingfederate_oauth_client.tech_pubs_web]
}

resource "pingfederate_sp_idp_connection" "harbor_mro_federation" {
  connection_id = "harbor-mro-federation"
  active        = true
  credentials = {
    certs = [
      {
        primary_verification_cert = true
        x509_file = {
          file_data = "-----BEGIN CERTIFICATE-----\nU1lOVEhFVElDIENFUlRJRklDQVRFIENOPUhhcmJvciBNUk8gU1NP\n-----END CERTIFICATE-----\n"
        }
      },
      {
        primary_verification_cert = true
        x509_file = {
          file_data = "-----BEGIN CERTIFICATE-----\nU1lOVEhFVElDIENFUlRJRklDQVRFIENOPXNzby5leGFtcGxlLWFlcm8udGVzdA==\n-----END CERTIFICATE-----\n"
        }
      },
    ]
  }
  entity_id = "https://sso.harbor-mro.example/idp"
  idp_browser_sso = {
    attribute_contract = {
      extended_attributes = [
        {
          name = "mail"
        },
        {
          name = "givenName"
        },
        {
          name = "sn"
        },
      ]
    }
    idp_identity_mapping = "ACCOUNT_MAPPING"
    jit_provisioning = {
      error_handling = "ABORT_SSO"
      event_trigger  = "NEW_USER_ONLY"
      user_attributes = {
        do_attribute_query = false
      }
      user_repository = {
        ldap = {
          base_dn = "ou=partners,ou=people,dc=partners,dc=example-aero,dc=test"
          data_store_ref = {
            id = "user-directory"
          }
          jit_repository_attribute_mapping = {
            givenName = {
              source = {
                type = "ASSERTION"
              }
              value = "givenName"
            }
            mail = {
              source = {
                type = "ASSERTION"
              }
              value = "mail"
            }
            sn = {
              source = {
                type = "ASSERTION"
              }
              value = "sn"
            }
          }
          unique_user_id_filter = "(mail=$${mail})"
        }
      }
    }
    protocol = "SAML20"
  }
  name       = "harbor-mro-federation"
  depends_on = [pingfederate_idp_sp_connection.customer_portal, pingfederate_idp_sp_connection.supplier_portal]
}

resource "pingfederate_sp_idp_connection" "skyline_air_federation" {
  connection_id = "skyline-air-federation"
  active        = true
  credentials = {
    certs = [
      {
        primary_verification_cert = true
        x509_file = {
          file_data = "-----BEGIN CERTIFICATE-----\nU1lOVEhFVElDIENFUlRJRklDQVRFIENOPVNreWxpbmUgQWlyIElkUCBTaWduaW5n\n-----END CERTIFICATE-----\n"
        }
      },
      {
        primary_verification_cert = true
        x509_file = {
          file_data = "-----BEGIN CERTIFICATE-----\nU1lOVEhFVElDIENFUlRJRklDQVRFIENOPXNzby5leGFtcGxlLWFlcm8udGVzdA==\n-----END CERTIFICATE-----\n"
        }
      },
    ]
  }
  entity_id = "https://idp.skyline-air.example/saml"
  idp_browser_sso = {
    attribute_contract = {
      extended_attributes = [
        {
          name = "mail"
        },
        {
          name = "givenName"
        },
        {
          name = "sn"
        },
      ]
    }
    idp_identity_mapping = "ACCOUNT_MAPPING"
    jit_provisioning = {
      error_handling = "ABORT_SSO"
      event_trigger  = "NEW_USER_ONLY"
      user_attributes = {
        do_attribute_query = false
      }
      user_repository = {
        ldap = {
          base_dn = "ou=partners,ou=people,dc=partners,dc=example-aero,dc=test"
          data_store_ref = {
            id = "user-directory"
          }
          jit_repository_attribute_mapping = {
            givenName = {
              source = {
                type = "ASSERTION"
              }
              value = "givenName"
            }
            mail = {
              source = {
                type = "ASSERTION"
              }
              value = "mail"
            }
            sn = {
              source = {
                type = "ASSERTION"
              }
              value = "sn"
            }
          }
          unique_user_id_filter = "(mail=$${mail})"
        }
      }
    }
    protocol = "SAML20"
  }
  name       = "skyline-air-federation"
  depends_on = [pingfederate_idp_sp_connection.customer_portal, pingfederate_idp_sp_connection.supplier_portal]
}

resource "pingfederate_server_settings" "serversettings" {
  contact_info = {
    company = "Example Aero"
    email   = "ciam-platform@example-aero.test"
  }
  federation_info = {
    base_url         = "https://sso.example-aero.test"
    saml_2_entity_id = "https://sso.example-aero.test/idp"
  }
  depends_on = [pingfederate_sp_idp_connection.harbor_mro_federation, pingfederate_sp_idp_connection.skyline_air_federation]
}
