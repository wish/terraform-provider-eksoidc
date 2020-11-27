package provider

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func New() *schema.Provider {
	return &schema.Provider{
		DataSourcesMap: map[string]*schema.Resource{},
		ResourcesMap: map[string]*schema.Resource{
			"eksoidc_key_document": resourceKeyDocument(),
		},
	}
}

func resourceKeyDocument() *schema.Resource {
	return &schema.Resource{
		CreateContext: CreateKeyDocument,
		ReadContext:   ReadKeyDocument,
		DeleteContext: DeleteKeyDocument,

		Schema: map[string]*schema.Schema{
			"cert_pem": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"document": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

type KeyResponse struct {
	Keys []jose.JSONWebKey `json:"keys"`
}

func CreateKeyDocument(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	content := d.Get("cert_pem").(string)
	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics

	block, _ := pem.Decode([]byte(content))
	if block == nil {
		return diag.FromErr(errors.Errorf("Error decoding PEM"))
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return diag.FromErr(errors.Wrapf(err, "Error parsing cert content"))
	}

	pubKey := cert.PublicKey
	switch pubKey.(type) {
	case *rsa.PublicKey:
	default:
		return diag.FromErr(errors.New("Public key was not RSA"))
	}

	var alg jose.SignatureAlgorithm
	switch pubKey.(type) {
	case *rsa.PublicKey:
		alg = jose.RS256
	default:
		return diag.FromErr(fmt.Errorf("invalid public key type %T, must be *rsa.PublicKey", pubKey))
	}

	kid, err := keyIDFromPublicKey(pubKey)
	if err != nil {
		return diag.FromErr(err)
	}

	var keys []jose.JSONWebKey
	keys = append(keys, jose.JSONWebKey{
		Key:       pubKey,
		KeyID:     kid,
		Algorithm: string(alg),
		Use:       "sig",
	})

	json, err := json.MarshalIndent(KeyResponse{Keys: keys}, "", "  ")
	if err != nil {
		return diag.FromErr(errors.Wrapf(err, "Error MarshalIndent"))
	}

	d.SetId(kid)
	d.Set("document", string(json))

	return diags
}

func DeleteKeyDocument(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics
	d.SetId("")
	return diags
}

func ReadKeyDocument(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	// Warning or errors can be collected in a slice type
	var diags diag.Diagnostics
	return diags
}

func keyIDFromPublicKey(publicKey interface{}) (string, error) {
	publicKeyDERBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to serialize public key to DER format: %v", err)
	}

	hasher := crypto.SHA256.New()
	hasher.Write(publicKeyDERBytes)
	publicKeyDERHash := hasher.Sum(nil)
	keyID := base64.RawURLEncoding.EncodeToString(publicKeyDERHash)

	return keyID, nil
}
