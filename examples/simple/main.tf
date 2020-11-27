terraform {
  required_providers {
    eksoidc = {
      versions = ["0.1"]
      source = "wish.com/wish/eksoidc"
    }
  }
}

provider "eksoidc" {}

resource "eksoidc_key_document" "document" {
  cert_pem = tls_self_signed_cert.cert.cert_pem
}

output "data" {
  value = {
    data = jsondecode(eksoidc_key_document.document.document)
    plain = eksoidc_key_document.document.document
  }
}


provider "tls" {}

resource "tls_private_key" "key" {
  algorithm = "RSA"
  rsa_bits  = "2048"
}

resource "tls_self_signed_cert" "cert" {
  key_algorithm   = "RSA"
  private_key_pem = tls_private_key.key.private_key_pem

  subject {
    common_name = "ca"
  }

  validity_period_hours = 87600
  is_ca_certificate     = true
  allowed_uses          = ["cert_signing", "crl_signing"]
}
