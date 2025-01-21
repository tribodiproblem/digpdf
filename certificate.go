package digpdf

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/ocsp"
)

// CertificateInfo is a struct holds the certificate information.
type CertificateInfo struct {
	IsCA               bool
	Version            int
	SerialNumber       string
	ValidAfter         time.Time
	ValidBefore        time.Time
	Subject            string
	Issuer             string
	PublicKeyAlgorithm string
	SignatureAlgorithm string
	SHA1Fingerprint    string

	// SelfSigned status is defined by comparing Subject with Issuer.
	SelfSigned bool

	// Trusted status is defined by checking the root certificate must include in the certificate pool.
	Trusted bool

	// Revoked status is defined by checking OCSP or CRL of the certificate.
	Revoked bool

	// Valid status is defined by comparing time.Now with ValidAfter and ValidBefore.
	Valid bool
}

// CertificateInfoList represent multiple CertificateInfo.
type CertificateInfoList []*CertificateInfo

// ReverseOrder is a method uses to reverse order certificate list.
func (c CertificateInfoList) ReverseOrder() {
	i := 0
	j := len(c) - 1
	for i < j {
		c[i], c[j] = c[j], c[i]
		i++
		j--
	}
}

// Certificates represent multiple x509.Certificate.
type Certificates []*x509.Certificate

// GetInfo is a method uses to get certificate information of each certificate.
func (c Certificates) GetInfo() CertificateInfoList {
	var certificateInfoList CertificateInfoList
	for _, certificate := range c {
		certificateInfoList = append(certificateInfoList, getCertificateInfo(certificate))
	}

	return certificateInfoList
}

func getCertificateInfo(certificate *x509.Certificate) *CertificateInfo {
	var certificateInfo CertificateInfo

	certificateInfo.IsCA = certificate.IsCA
	certificateInfo.Version = certificate.Version
	certificateInfo.ValidAfter = certificate.NotBefore
	certificateInfo.ValidBefore = certificate.NotAfter
	certificateInfo.Issuer = certificate.Issuer.CommonName
	certificateInfo.Subject = certificate.Subject.String()
	certificateInfo.SerialNumber = getCertificateSerialNumber(certificate)
	certificateInfo.PublicKeyAlgorithm = getCertificatePublicKeyAlgorithm(certificate)
	certificateInfo.SignatureAlgorithm = getCertificateSignatureAlgorithm(certificate)
	certificateInfo.SHA1Fingerprint = getCertificateFingerprint(certificate)
	certificateInfo.SelfSigned = getSelfSignedStatus(certificate)
	certificateInfo.Valid = getCertificateValidityStatus(certificate)
	// certificateInfo.Revoked = getCertificateRevocationStatus(certificate)

	return &certificateInfo
}

func getCertificateSerialNumber(certificate *x509.Certificate) string {
	return fmt.Sprintf("%X", certificate.SerialNumber)
}

func getCertificatePublicKeyAlgorithm(certificate *x509.Certificate) string {
	var keyLen string
	switch certificate.PublicKeyAlgorithm {
	case x509.RSA:
		if rsaKey, ok := certificate.PublicKey.(*rsa.PublicKey); ok {
			keyLen = fmt.Sprintf(" (%d bit)", rsaKey.N.BitLen())
		}
	case x509.DSA:
		keyLen = ""
	case x509.ECDSA:
		if ecdsaKey, ok := certificate.PublicKey.(*ecdsa.PublicKey); ok {
			keyLen = fmt.Sprintf(" (%d bit)", ecdsaKey.Params().BitSize)
		}
	default:
		keyLen = ""
	}

	if 0 < certificate.PublicKeyAlgorithm && int(certificate.PublicKeyAlgorithm) < len(publicKeyAlgoName) {
		return publicKeyAlgoName[certificate.PublicKeyAlgorithm] + keyLen
	}

	return strconv.Itoa(int(certificate.PublicKeyAlgorithm))
}

func getCertificateSignatureAlgorithm(certificate *x509.Certificate) string {
	for _, details := range signatureAlgorithmDetails {
		if details.algo == certificate.SignatureAlgorithm {
			return details.name
		}
	}

	return strconv.Itoa(int(certificate.SignatureAlgorithm))
}

func getCertificateFingerprint(certificate *x509.Certificate) string {
	return CalculateFingerprint(sha1.New(), certificate.Raw)
}

func getSelfSignedStatus(certificate *x509.Certificate) bool {
	return certificate.Issuer.String() == certificate.Subject.String()
}

func getCertificateValidityStatus(certificate *x509.Certificate) bool {
	if time.Now().Before(certificate.NotAfter) && time.Now().After(certificate.NotBefore) {
		return true
	}

	return false
}

const (
	// maxTimeout holds default max waiting time when
	// performing http request.
	maxTimeout time.Duration = 2

	// maxIdleConn holds default maximum idle connection when
	// performing http request.
	maxIdleConn int = 100

	// maxConnPerHost holds default maximum connection per host when
	// performing http request.
	maxConnPerHost int = 100

	// maxIdleConnPerHost holds default maximum idle connection per host when
	// performing http request.
	maxIdleConnPerHost int = 100
)

func getCertificateRevocationStatus(certificate *x509.Certificate) bool {
	var revoked = false
	for _, url := range certificate.CRLDistributionPoints {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.MaxIdleConns = maxIdleConn
		t.MaxConnsPerHost = maxConnPerHost
		t.MaxIdleConnsPerHost = maxIdleConnPerHost

		HTTPClient := &http.Client{
			Timeout:   maxTimeout * time.Second,
			Transport: t,
		}

		resp, err := HTTPClient.Get(url)
		if err != nil {
			return false
		}

		if resp.StatusCode >= 300 {
			return false
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return false
		}

		crl, err := x509.ParseCRL(body)
		if err != nil {
			return false
		}

		for _, revokedCertificate := range crl.TBSCertList.RevokedCertificates {
			if certificate.SerialNumber.Cmp(revokedCertificate.SerialNumber) == 0 {
				revoked = true
			}
		}
	}

	return revoked
}

func getCertificateRevocationStatusByOCSP(ocspResponse *ocsp.Response) bool {
	if ocspResponse.Status == ocsp.Revoked {
		return false
	}

	if ocspResponse.Status != ocsp.Good {
		return false
	}

	return true
}

func getCertificateRevocationInfoByCRL(certificate *x509.Certificate) bool {
	return getCertificateValidityStatus(certificate)
}
