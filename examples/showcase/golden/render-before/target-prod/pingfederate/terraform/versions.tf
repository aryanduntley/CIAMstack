terraform {
  required_providers {
    pingfederate = {
      source  = "pingidentity/pingfederate"
      version = "1.10.0"
    }
  }
}

provider "pingfederate" {
  https_host      = var.pingfederate_https_host
  product_version = "13.1"
}
