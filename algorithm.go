package digremover

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
)

var publicKeyAlgoName = [...]string{
	x509.RSA:     "RSA",
	x509.DSA:     "DSA",
	x509.ECDSA:   "ECDSA",
	x509.Ed25519: "Ed25519",
}

var signatureAlgorithmDetails = []struct {
	algo       x509.SignatureAlgorithm
	name       string
	pubKeyAlgo x509.PublicKeyAlgorithm
	hash       crypto.Hash
}{
	{x509.MD2WithRSA, "MD2-RSA", x509.RSA, crypto.Hash(0) /* no value for MD2 */},
	{x509.MD5WithRSA, "MD5-RSA", x509.RSA, crypto.MD5},
	{x509.SHA1WithRSA, "SHA1-RSA", x509.RSA, crypto.SHA1},
	{x509.SHA1WithRSA, "SHA1-RSA", x509.RSA, crypto.SHA1},
	{x509.SHA256WithRSA, "SHA256-RSA", x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSA, "SHA384-RSA", x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSA, "SHA512-RSA", x509.RSA, crypto.SHA512},
	{x509.SHA256WithRSAPSS, "SHA256-RSAPSS", x509.RSA, crypto.SHA256},
	{x509.SHA384WithRSAPSS, "SHA384-RSAPSS", x509.RSA, crypto.SHA384},
	{x509.SHA512WithRSAPSS, "SHA512-RSAPSS", x509.RSA, crypto.SHA512},
	{x509.DSAWithSHA1, "DSA-SHA1", x509.DSA, crypto.SHA1},
	{x509.DSAWithSHA256, "DSA-SHA256", x509.DSA, crypto.SHA256},
	{x509.ECDSAWithSHA1, "ECDSA-SHA1", x509.ECDSA, crypto.SHA1},
	{x509.ECDSAWithSHA256, "ECDSA-SHA256", x509.ECDSA, crypto.SHA256},
	{x509.ECDSAWithSHA384, "ECDSA-SHA384", x509.ECDSA, crypto.SHA384},
	{x509.ECDSAWithSHA512, "ECDSA-SHA512", x509.ECDSA, crypto.SHA512},
	{x509.PureEd25519, "Ed25519", x509.Ed25519, crypto.Hash(0) /* no pre-hashing */},
}

var hashOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA1:   asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26}),
	crypto.SHA256: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 1}),
	crypto.SHA384: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 2}),
	crypto.SHA512: asn1.ObjectIdentifier([]int{2, 16, 840, 1, 101, 3, 4, 2, 3}),
}
