package digremover

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"golang.org/x/crypto/ocsp"
)

// Metadata is a struct holds metadata of PDF file.
type Metadata struct {
	Title    string   `json:"title,omitempty"`
	Subject  string   `json:"subject,omitempty"`
	Category string   `json:"category,omitempty"`
	Author   string   `json:"author,omitempty"`
	Keywords []string `json:"keywords,omitempty"`
}

// RevocationInfo is a struct holds ocsps and crls.
type RevocationInfo struct {
	Base16cert string
	CRLS       []*pkix.CertificateList
	OCSPS      []*ocsp.Response
	Certs      []*x509.Certificate
}

// revocationInfoArchival is a struct for unmarshal of signed attribute RevocationInfoArchival.
type revocationInfoArchival struct {
	CRL          []asn1.RawValue `asn1:"optional,omitempty,tag:0"`
	OCSP         []asn1.RawValue `asn1:"optional,omitempty,tag:1"`
	OtherRevInfo []asn1.RawValue `asn1:"optional,omitempty,tag:2"`
}
