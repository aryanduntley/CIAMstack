terraform {
  required_providers {
    pingfederate = {
      source  = "pingidentity/pingfederate"
      version = "1.8.1"
    }
  }
}

provider "pingfederate" {
  https_host      = var.pingfederate_https_host
  product_version = "12.1"
}
