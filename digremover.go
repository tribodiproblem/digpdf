package digpdf

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/tribodiproblem/fvckpdf/pkg/api"
	"github.com/tribodiproblem/fvckpdf/pkg/pdfcpu"
	"go.mozilla.org/pkcs7"
	"golang.org/x/crypto/ocsp"
)

const (
	// TypeSigned represent type of digital signature field is signature.
	TypeSigned Type = iota

	// TypeCertified represent type of digital signature field is certify.
	TypeCertified
)

// PDFCertifyFlag is a TransformMethod value in the PDF signature reference
// which is represented that PDF is certified.
const PDFCertifyFlag pdfcpu.Name = "DocMDP"

// Type represent type of digital signature.
type Type int

// PDFSignature is a struct holds i/o and metadata.
// It used to fetch digital signatures' information from the PDF file.
type PDFSignature struct {
	inputFilePath   string
	outputFilePath  string
	configuration   *pdfcpu.Configuration
	metadata        *Metadata
	ltvInfo         bool
	integrityInfo   bool
	certificateInfo bool
}

// Signature is a struct holds detailed information about digital signature.
type Signature struct {
	Field        string              `json:"field,omitempty"`
	Visible      bool                `json:"visible,omitempty"`
	Name         string              `json:"name,omitempty"`
	Location     string              `json:"location,omitempty"`
	Reason       string              `json:"reason,omitempty"`
	SignedAt     string              `json:"signed_at,omitempty"`
	Timestamp    time.Time           `json:"timestamp"`
	Timestamped  bool                `json:"timestamped,omitempty"`
	Integrity    bool                `json:"integrity,omitempty"`
	LTVSupport   bool                `json:"ltv_support,omitempty"`
	Issuer       string              `json:"issuer,omitempty"`
	Type         Type                `json:"type,omitempty"`
	Certificates CertificateInfoList `json:"certificates,omitempty"`
}

// Signatures represent multiple Signature.
type Signatures []*Signature

// New is a constructor will initialize PDFSignature.
func New(filePath string, opts ...Option) *PDFSignature {
	pdfSignature := &PDFSignature{
		configuration: defaultConfiguration,
		inputFilePath: filePath,
	}

	for _, opt := range opts {
		opt(pdfSignature)
	}

	return pdfSignature
}

var defaultConfiguration = pdfcpu.NewDefaultConfiguration()

// RemoveDigitalSignatures is a function uses to remove digital signatures from PDF file.
func (p *PDFSignature) RemoveDigitalSignatures(outputFilePath string) (bool, error) {
	// get PDF context
	pdfContext, errGetContext := pdfcpu.ReadFile(p.inputFilePath, p.configuration)
	if errGetContext != nil {
		return false, errGetContext
	}

	// try remove QRCode with core logic first
	newPdfContext, _, err := p.removeWatermarkQRCode()
	if err != nil {
		log.Println("cannot remove qr code, err: ", err)
	}

	if newPdfContext != nil {
		pdfContext = newPdfContext
	}

	// then, try remove QRCode with new core logic
	_, err = p.removeXObjectRQCode(pdfContext)
	if err != nil {
		log.Println("cannot remove qr code, err: ", err)
	}

	// parse Acro Form fields
	pdfAcroFormFieldsArray, errParseAcroFormFields := getSignatureFieldsArray(pdfContext)
	if errParseAcroFormFields != nil {
		return false, errParseAcroFormFields
	}

	// loop each Acro Form fields
	for _, field := range pdfAcroFormFieldsArray {
		// cast field as IndirectRef, now we have annotation
		annotationReference, ok := field.(pdfcpu.IndirectRef)
		if !ok {
			log.Println("cannot cast indirect reference")
		}

		// parse annotation into annotation dictionary
		annotationDict, err := pdfContext.DereferenceDict(annotationReference)
		if err != nil {
			log.Println("cannot deference dictionary")
		}

		if annotationDict == nil {
			return false, nil
		}

		// try to find object with "V" key
		v, found := annotationDict.Find("V")
		if !found {
			log.Println("found v")
		}

		// parse V object into signature dictionary
		signatureDict, err := pdfContext.DereferenceDict(v)
		if err != nil {
			log.Println("cannot deference dictionary")
		}

		if signatureDict == nil {
			return false, nil
		}

		// ensure signature dictionary is not nil
		// it represents that dictionary may contains signature content (image, text, cert)
		_, found = signatureDict.Find("Contents")

		if !found {
			return false, nil
		}

		// delete signature image and certificate
		err = pdfContext.DeleteObject(v.(pdfcpu.IndirectRef).ObjectNumber.Value())
		if err != nil {
			return false, err
		}

		err = pdfContext.DeleteObject(annotationReference.ObjectNumber.Value())
		if err != nil {
			return false, err
		}
	}

	return WritePDF(pdfContext, outputFilePath, p.configuration, p.metadata)
}

func (p *PDFSignature) removeWatermarkQRCode() (*pdfcpu.Context, bool, error) {
	// try to remove QR code
	hasWatermark, err := api.HasWatermarksFile(p.inputFilePath, p.configuration)
	if err != nil {
		return nil, false, err
	}

	if !hasWatermark {
		return nil, false, nil
	}

	pdfTempFile, err := ioutil.TempFile("/tmp", "document-*.pdf")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(pdfTempFile.Name())

	errRemoveWatermark := api.RemoveWatermarksFile(p.inputFilePath, pdfTempFile.Name(), nil, p.configuration)
	if errRemoveWatermark != nil {
		return nil, false, errRemoveWatermark
	}

	pdfContext, errGetContext := pdfcpu.ReadFile(pdfTempFile.Name(), p.configuration)
	if errGetContext != nil {
		return nil, false, errGetContext
	}

	return pdfContext, true, nil
}

//gocyclo:ignore
func (p *PDFSignature) removeXObjectRQCode(pdfContext *pdfcpu.Context) (bool, error) {
	// initial state
	foundQRCode := false

	// get PDF pages - kids
	pdfCatalogDict, _ := pdfContext.Catalog()
	pdfPagesObj, _ := pdfCatalogDict.Find("Pages")
	pdfPagesDict, _ := pdfContext.DereferenceDict(pdfPagesObj)
	pdfPagesKidsObj, _ := pdfPagesDict.Find("Kids")
	pdfPagesKidsArray, _ := pdfContext.DereferenceArray(pdfPagesKidsObj)
	if pdfPagesKidsArray == nil {
		return false, nil
	}

	for _, kid := range pdfPagesKidsArray {
		// cast kid as IndirectRef
		kidReference, ok := kid.(pdfcpu.IndirectRef)
		if !ok {
			continue
		}

		// parse kid into kid dictionary
		kidDict, err := pdfContext.DereferenceDict(kidReference)
		if err != nil {
			continue
		}
		if kidDict == nil {
			continue
		}

		// fetch kid annotations
		kidAnnotsObj, _ := kidDict.Find("Annots")
		// parse kid annotations into kid annotations array
		kidAnnotsArray, err := pdfContext.DereferenceArray(kidAnnotsObj)
		if err != nil {
			continue
		}
		if kidAnnotsArray == nil {
			continue
		}

		// fetch kid resources
		kidResourcesObj, _ := kidDict.Find("Resources")

		// parse kid resources into kid resources dictionary
		kidResourcesDict, err := pdfContext.DereferenceDict(kidResourcesObj)
		if err != nil {
			continue
		}
		if kidResourcesDict == nil {
			continue
		}

		// fetch XObject
		xObjectObj, found := kidResourcesDict.Find("XObject")
		if !found {
			continue
		}

		// parse XObject into XObject dictionary
		xObjectDict, err := pdfContext.DereferenceDict(xObjectObj)
		if err != nil {
			continue
		}
		if xObjectDict == nil {
			continue
		}

		// delete X0 object
		xObjectX0Obj, foundXObjectX0Obj := xObjectDict.Find("X0")
		if foundXObjectX0Obj {
			foundQRCode = foundXObjectX0Obj
			err = pdfContext.DeleteObject(xObjectX0Obj.(pdfcpu.IndirectRef).ObjectNumber.Value())
			if err != nil {
				continue
			}
		}

		// delete X1 object
		xObjectX1Obj, foundXObjectX1Obj := xObjectDict.Find("X1")
		if foundXObjectX1Obj {
			foundQRCode = foundXObjectX1Obj
			err = pdfContext.DeleteObject(xObjectX1Obj.(pdfcpu.IndirectRef).ObjectNumber.Value())
			if err != nil {
				continue
			}
		}

		// delete X3 object
		xObjectX3Obj, foundXObjectX3Obj := xObjectDict.Find("X3")
		if foundXObjectX3Obj {
			foundQRCode = foundXObjectX3Obj
			err = pdfContext.DeleteObject(xObjectX3Obj.(pdfcpu.IndirectRef).ObjectNumber.Value())
			if err != nil {
				continue
			}
		}

		// delete R19 object
		xObjectR19Obj, foundXObjectR19Obj := xObjectDict.Find("R19")
		if foundXObjectR19Obj {
			foundQRCode = foundXObjectR19Obj
			err = pdfContext.DeleteObject(xObjectR19Obj.(pdfcpu.IndirectRef).ObjectNumber.Value())
			if err != nil {
				continue
			}
		}

		// delete I1 object
		xObjectI1Obj, foundXObjectI1Obj := xObjectDict.Find("I1")
		if foundXObjectI1Obj {
			foundQRCode = foundXObjectI1Obj
			err = pdfContext.DeleteObject(xObjectI1Obj.(pdfcpu.IndirectRef).ObjectNumber.Value())
			if err != nil {
				continue
			}
		}

		// delete XO1 object
		xObjectXO1Obj, foundXObjectXO1Obj := xObjectDict.Find("XO1")
		if foundXObjectXO1Obj {
			foundQRCode = foundXObjectXO1Obj
			err = pdfContext.DeleteObject(xObjectXO1Obj.(pdfcpu.IndirectRef).ObjectNumber.Value())
			if err != nil {
				continue
			}
		}

		// delete XO2 object
		xObjectXO2Obj, foundXObjectXO2Obj := xObjectDict.Find("XO2")
		if foundXObjectXO2Obj {
			foundQRCode = foundXObjectXO2Obj
			err = pdfContext.DeleteObject(xObjectXO2Obj.(pdfcpu.IndirectRef).ObjectNumber.Value())
			if err != nil {
				continue
			}
		}

		// delete XO3 object
		xObjectXO3Obj, foundXObjectXO3Obj := xObjectDict.Find("XO3")
		if foundXObjectXO3Obj {
			foundQRCode = foundXObjectXO3Obj
			err = pdfContext.DeleteObject(xObjectXO3Obj.(pdfcpu.IndirectRef).ObjectNumber.Value())
			if err != nil {
				continue
			}
		}

		// delete R72 object
		xObjectR72Obj, foundXObjectR72Obj := xObjectDict.Find("R72")
		if foundXObjectR72Obj {
			foundQRCode = foundXObjectR72Obj
			err = pdfContext.DeleteObject(xObjectR72Obj.(pdfcpu.IndirectRef).ObjectNumber.Value())
			if err != nil {
				continue
			}
		}

		xObjectXO3Obj, foundXObjectXO3Obj = xObjectDict.Find("Fm0")
		if foundXObjectXO3Obj {
			foundQRCode = foundXObjectXO3Obj
			err = pdfContext.DeleteObject(xObjectXO3Obj.(pdfcpu.IndirectRef).ObjectNumber.Value())
			if err != nil {
				continue
			}
		}

		// delete X5 object
		xObjectX5Obj, foundXObjectX5Obj := xObjectDict.Find("X5")
		if foundXObjectX5Obj {
			foundQRCode = foundXObjectX5Obj
			err = pdfContext.DeleteObject(xObjectX5Obj.(pdfcpu.IndirectRef).ObjectNumber.Value())
			if err != nil {
				continue
			}
		}
	}

	if !foundQRCode {
		log.Println("Previous qr code not found")
	}

	return foundQRCode, nil
}

func (p *PDFSignature) getSignatureInformation(pdfContext *pdfcpu.Context, annotationDict pdfcpu.Dict, signatureDict pdfcpu.Dict) Signature {
	// populate signature info
	var signature Signature

	// default type is signature
	signature.Type = TypeSigned

	// fetch signature field name
	signatureFieldName, found := annotationDict.Find("T")
	if found {
		signature.Field, _ = pdfContext.DereferenceText(signatureFieldName)
	}

	// fetch signatory name
	signatureName, found := signatureDict.Find("Name")
	if found {
		signature.Name, _ = pdfContext.DereferenceText(signatureName)
	}

	// fetch signatory location
	signatureLocation, found := signatureDict.Find("Location")
	if found {
		signature.Location, _ = pdfContext.DereferenceText(signatureLocation)
	}

	// fetch signatory reason
	signatureReason, found := signatureDict.Find("Reason")
	if found {
		signature.Reason, _ = pdfContext.DereferenceText(signatureReason)
	}

	// fetch signatory time (local)
	signatureTimestamp, found := signatureDict.Find("M")
	if found {
		strSignatureTimeRaw, _ := pdfContext.DereferenceText(signatureTimestamp)
		strSignatureTimeClean := strings.ReplaceAll(strings.Split(strSignatureTimeRaw, ":")[1], "'", "")
		strSignatureTime, _ := time.Parse("20060102150405-0700", strSignatureTimeClean)
		signature.SignedAt = strSignatureTime.Format(time.RFC3339)
	}

	return signature
}

func getSignatureFieldsArray(pdfContext *pdfcpu.Context) (pdfcpu.Array, error) {
	// retrieve Root dictionary
	pdfRootDict := pdfContext.RootDict

	// find Acro Form object
	pdfAcroFormObj, foundAcroFormObj := pdfRootDict.Find("AcroForm")
	if !foundAcroFormObj {
		return nil, nil
	}

	// parse Acro Form dictionary
	pdfAcroFormDict, errParseAcroForm := pdfContext.DereferenceDict(pdfAcroFormObj)
	if errParseAcroForm != nil {
		return nil, errParseAcroForm
	}

	// find Acro Form fields
	pdfAcroFormFields, foundAcroFormFields := pdfAcroFormDict.Find("Fields")
	if !foundAcroFormFields {
		return nil, nil
	}

	// parse Acro Form fields
	pdfAcroFormFieldsArray, errParseAcroFormFields := pdfContext.DereferenceArray(pdfAcroFormFields)
	if errParseAcroFormFields != nil {
		return nil, errParseAcroFormFields
	}

	return pdfAcroFormFieldsArray, nil
}

func getSignatureSigningTime(signature *pkcs7.PKCS7) (time.Time, error) {
	var signingTimestamp time.Time

	signers := signature.Signers
	if len(signers) != 1 {
		return signingTimestamp, errors.New("the number of signers must be exactly 1")
	}

	signer := signers[0]

	// signingTime is 1.2.840.113549.1.9.5
	// it should be part of the authenticated attributes for a CAdES signature
	var OIDAttributeSigningTime = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	for _, authAttr := range signer.AuthenticatedAttributes {

		if authAttr.Type.Equal(OIDAttributeSigningTime) {
			signingTimeBytes := authAttr.Value.Bytes
			_, _ = asn1.Unmarshal(signingTimeBytes, &signingTimestamp)

			return signingTimestamp, nil
		}
	}

	return signingTimestamp, errors.New("no signer time in pkcs7")
}

func getSignatureTimestamp(signatureDict pdfcpu.Dict) (time.Time, bool, error) {
	var signatureTimestamp time.Time
	var signatureBytes []byte

	// fetch contents from signature dictionary
	contents, found := signatureDict.Find("Contents")
	if !found {
		return signatureTimestamp, false, nil
	}

	// fetch signature from the contents
	switch contents := contents.(type) {
	case pdfcpu.StringLiteral:
		contentsStringLiteral := contents
		signatureBytes = []byte(contentsStringLiteral.String())
	case pdfcpu.HexLiteral:
		contentsHexLiteral := contents
		signBytes, err := contentsHexLiteral.Bytes()
		if err != nil {
			return signatureTimestamp, false, err
		}
		signatureBytes = signBytes
	}

	if len(signatureBytes) == 0 {
		return signatureTimestamp, false, nil
	}

	// parse signature
	signature, err := pkcs7.Parse(signatureBytes)
	if err != nil {
		return signatureTimestamp, false, nil
	}

	// get the signer
	signers := signature.Signers
	if len(signers) != 1 {
		return signatureTimestamp, false, errors.New("the number of signers must be exactly 1")
	}
	signer := signers[0]

	// the timestamp is included in the "SignerInfo" as an unauthenticated attribute
	// the timestamp is a CADES signature of the "authenticated attributes"
	unAuthAttributes := signer.UnauthenticatedAttributes
	for _, unAuthAttr := range unAuthAttributes {

		// timestamp is 1.2.840.113549.1.9.16.2.14 according to RFC3161 (Appendix A)
		// os this attribute the MessageDigest?
		var OIDAttributeTimestamp = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}
		if unAuthAttr.Type.Equal(OIDAttributeTimestamp) {
			signatureTimestampBytes := unAuthAttr.Value.Bytes

			signaturePKCS7, err := pkcs7.Parse(signatureTimestampBytes)
			if err != nil {
				return signatureTimestamp, false, err
			}

			signatureTimestamp, err = getSignatureSigningTime(signaturePKCS7)
			if err != nil {
				return signatureTimestamp, false, err
			}

			return signatureTimestamp, true, nil
		}
	}

	return signatureTimestamp, false, errors.New("no timestamp found in pkcs7")
}

type signerInfo struct {
	Version                   int `asn1:"default:1"`
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"optional,omitempty,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []attribute `asn1:"optional,omitempty,tag:1"`
}

type attribute struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

func getSignatureIntegrity(inputFilePath string, signatureDict pdfcpu.Dict) (bool, error) {
	var verified bool
	var byteRangeArray pdfcpu.Array

	// fetch ByteRange to get the bytes which will form the hash
	byteRange, found := signatureDict.Find("ByteRange")
	if !found {
		return false, nil
	}

	// byteRange is an array - cast to pdfcpu.Array
	byteRangeArray = byteRange.(pdfcpu.Array)

	// the byte range indicates the portion of the document to be signed
	// for further information, please check this document:
	// https://www.adobe.com/devnet-docs/acrobatetk/tools/DigSig/Acrobat_DigitalSignatures_in_PDF.pdf
	// also:
	// https://security.stackexchange.com/questions/35121/a-standard-way-to-manually-add-a-digital-signature-to-a-pdf-file/35131#35131

	// according to the document above:
	// the byteRangeArray has four positions
	// position 0 indicates the beginning
	// between positions 1 and 2 is the signature
	// position 3 indicates the length from the signature to the end of the file
	posBeforeSig := byteRangeArray[0].(pdfcpu.Integer)
	lenBeforeSig := byteRangeArray[1].(pdfcpu.Integer)
	posAfterSig := byteRangeArray[2].(pdfcpu.Integer)
	lenAfterSig := byteRangeArray[3].(pdfcpu.Integer)

	// open pdf file
	pdfFile, err := os.Open(inputFilePath)
	if err != nil {
		return false, err
	}

	// read the document portion located before the signature
	byteSliceBefore := make([]byte, lenBeforeSig)
	_, _ = pdfFile.ReadAt(byteSliceBefore, int64(posBeforeSig))

	// read the document portion located after the signature
	byteSliceAfter := make([]byte, lenAfterSig)
	_, _ = pdfFile.ReadAt(byteSliceAfter, int64(posAfterSig))

	// concatenate the two read portions
	byteSliceBefore = append(byteSliceBefore, byteSliceAfter...)

	// next, we need to compare the hash of pdfContent with messageDigest
	// fetch contents from signature dictionary
	contents, found := signatureDict.Find("Contents")
	if !found {
		return false, nil
	}

	// fetch signature from the contents
	contentsHexLiteral := contents.(pdfcpu.HexLiteral).Clone()
	signatureBytes, err := contentsHexLiteral.(pdfcpu.HexLiteral).Bytes()
	if err != nil {
		return false, err
	}

	// parse signature
	signature, err := pkcs7.Parse(signatureBytes)
	if err != nil {
		return false, err
	}

	// fetch signers
	signers := signature.Signers
	signer := signers[0]

	// the message digest is one of the authenticated attributes
	signerAuthAttr := signer.AuthenticatedAttributes

	// try to find the message digest
	var messageDigest []byte
	for _, authAttr := range signerAuthAttr {

		// signingTime is 1.2.840.113549.1.9.5
		// os this attribute the MessageDigest?
		var OIDAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
		if !authAttr.Type.Equal(OIDAttributeMessageDigest) {
			continue
		}

		// unmarshall authenticated attribute (messageDigest)
		_, err := asn1.Unmarshal(authAttr.Value.Bytes, &messageDigest)
		if err != nil {
			return false, err
		}
	}

	if len(messageDigest) == 0 {
		return false, errors.New("message digest not found among authenticated attributes")
	}

	// find out the digest algorithm
	// hash := crypto.SHA256
	hashPDF, err := getDigestAlgorithmFromOid(signer.DigestAlgorithm.Algorithm)
	if err != nil {
		return false, err
	}
	hash := *hashPDF

	// calculate message hash
	h := hash.New()
	h.Write(byteSliceBefore)
	computed := h.Sum(make([]byte, 0))

	if bytes.Compare(computed, messageDigest) == 0 {
		verified = true
	} else {
		verified = false
	}

	return verified, nil
}

func getSignatureLTV(pdfContext *pdfcpu.Context, signatureDict pdfcpu.Dict) (bool, RevocationInfo, error) {
	// init revocation info
	var revocationInfo RevocationInfo

	// fetch contents from signature dictionary
	contents, found := signatureDict.Find("Contents")
	if !found {
		return false, revocationInfo, nil
	}

	// fetch signature from the contents
	contentsHexLiteral := contents.(pdfcpu.HexLiteral)
	signatureBytes, err := contentsHexLiteral.Bytes()
	if err != nil {
		return false, revocationInfo, err
	}

	var ltvSupport = false

	found, revocationInfo, _ = getSignatureRevocationInfo(pdfContext, signatureBytes)
	if !found {
		return false, revocationInfo, nil
	}

	if len(revocationInfo.OCSPS) > 0 {
		var ocspIsOK = false
		for _, ocspResponse := range revocationInfo.OCSPS {
			ocspIsOK = getCertificateRevocationStatusByOCSP(ocspResponse)
			fmt.Println(ocspIsOK)
		}

		ltvSupport = ocspIsOK
	}

	if len(revocationInfo.CRLS) > 0 {
		var crlIsOK = false
		for _, certificate := range revocationInfo.Certs {
			crlIsOK = getCertificateRevocationInfoByCRL(certificate)
			fmt.Println(crlIsOK)
		}

		ltvSupport = crlIsOK
	}

	return ltvSupport, revocationInfo, nil
}

func getSignatureRevocationInfo(pdfContext *pdfcpu.Context, signatureBytes []byte) (bool, RevocationInfo, error) {
	found, revocationInfo, _ := getRevocationInfoFromSigners(signatureBytes)
	if found {
		return true, revocationInfo, nil
	}

	found, revocationInfo, _ = getRevocationInfoFromDSSDictionary(pdfContext)
	if found {
		return true, revocationInfo, nil
	}

	found, revocationInfo, _ = getRevocationInfoFromVRIDictionary(pdfContext, signatureBytes)
	if found {
		return true, revocationInfo, nil
	}

	return false, revocationInfo, nil
}

func getRevocationInfoFromSigners(signatureBytes []byte) (bool, RevocationInfo, error) {
	// init revocation info
	var revocationInfo RevocationInfo

	// parse signature
	// It's oke to ignore error when parsing with pkcs7 to get the certificate
	// because some signature bytes does not contain cert object directly
	// example pdf: signed with DocuSign
	signature, err := pkcs7.Parse(signatureBytes)
	if err != nil {
		return false, revocationInfo, err
	}

	// fetch signers
	signers := signature.Signers

	// get the signer
	if len(signers) != 1 {
		return false, revocationInfo, errors.New("the number of signers must be exactly 1")
	}
	signer := signers[0]

	// the message digest is one of the authenticated attributes
	signerAuthAttr := signer.AuthenticatedAttributes
	for _, authAttr := range signerAuthAttr {
		// the revocation info is embedded in the signature
		// as signed attribute with OID 1.2.840.113583.1.1.8
		var OIDAttributeRevocationInfo = asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 8}
		if !authAttr.Type.Equal(OIDAttributeRevocationInfo) {
			continue
		}

		// fetch ocsp bytes
		ocspBytes := authAttr.Value.Bytes

		// ocspBytes is an ASN.1 encoded object, containing CRLs and OCSPs
		var ri revocationInfoArchival
		_, err := asn1.Unmarshal(ocspBytes, &ri)
		if err != nil {
			return false, revocationInfo, err
		}

		revocationInfo.OCSPS = make([]*ocsp.Response, len(ri.OCSP))
		if len(ri.OCSP) > 0 {
			ocspResponse, err := ocsp.ParseResponse(ri.OCSP[0].Bytes, nil)
			if err != nil {
				return false, revocationInfo, err
			}

			revocationInfo.OCSPS[0] = ocspResponse
		}

		revocationInfo.CRLS = make([]*pkix.CertificateList, len(ri.CRL))
		if len(ri.CRL) > 0 {
			crl, err := x509.ParseCRL(ri.CRL[0].Bytes)
			if err != nil {
				return false, revocationInfo, err
			}

			revocationInfo.CRLS[0] = crl
		}

		// either the CRL or the OCSP might be empty, but not both of them
		if len(ri.OCSP) == 0 && len(ri.CRL) == 0 {
			return false, revocationInfo, errors.New("ocsp array and crl array are empty")
		}

		return true, revocationInfo, nil
	}

	return false, revocationInfo, nil
}

func getRevocationInfoFromDSSDictionary(pdfContext *pdfcpu.Context) (bool, RevocationInfo, error) {
	// init revocation info
	var revocationInfo RevocationInfo

	// access the Root Dictionary
	rootDict := pdfContext.RootDict

	// find DSS Dictionary inside Root Dictionary
	dssDictRef, found := rootDict.Find("DSS")
	if !found {
		return false, revocationInfo, errors.New("dss dictionary not found")
	}

	// DSS object is an indirect object pointing to the DSS dictionary
	dict, err := pdfContext.DereferenceDict(dssDictRef)
	if err != nil {
		return false, revocationInfo, err
	}

	revocationInfo.Certs, _ = getRevocationInfoCertObj(pdfContext, dict, "Certs")
	revocationInfo.OCSPS, _ = getRevocationInfoOCSPSObj(pdfContext, dict, "OCSPs")
	revocationInfo.CRLS, _ = getRevocationInfoCRLSObj(pdfContext, dict, "CRLs")

	if len(revocationInfo.Certs) > 0 || len(revocationInfo.OCSPS) > 0 || len(revocationInfo.CRLS) > 0 {
		return true, revocationInfo, nil
	}

	return false, revocationInfo, nil
}

func getRevocationInfoFromVRIDictionary(pdfContext *pdfcpu.Context, signatureBytes []byte) (bool, RevocationInfo, error) {
	// init revocation info
	var revocationInfo RevocationInfo

	// the index of the vri dictionary entry is the base-16-encoded (uppercase)
	// SHA1 digest of the signature to which it applies
	hash := sha1.New()
	hash.Write(signatureBytes)

	// hashBytes is encoded in base16
	hashBytes := hash.Sum(nil)
	base16str := strings.ToUpper(hex.EncodeToString(hashBytes))

	revocationInfo.Base16cert = base16str

	// access the Root Dictionary
	rootDict := pdfContext.RootDict

	// find DSS Dictionary inside Root Dictionary
	dssDictRef, found := rootDict.Find("DSS")
	if !found {
		return false, revocationInfo, errors.New("dss dictionary not found")
	}

	// DSS object is an indirect object pointing to the DSS dictionary
	dssDict, err := pdfContext.DereferenceDict(dssDictRef)
	if err != nil {
		return false, revocationInfo, err
	}

	// find VRI dictionary
	vriDictRef, found := dssDict.Find("VRI")
	if !found {
		return false, revocationInfo, errors.New("vri dictionary not found")
	}

	// VRI object is an indirect object pointing to the VRI dictionary
	vriDict, err := pdfContext.DereferenceDict(vriDictRef)
	if err != nil {
		return false, revocationInfo, err
	}

	// the value is the Signature VRI dictionary
	// which contains the validation-related information for that signature
	vriEntry, err := vriDict.Entry("VRI", base16str, true)
	if err != nil {
		return false, revocationInfo, err
	}

	dict, err := pdfContext.DereferenceDict(vriEntry)
	if err != nil {
		return false, revocationInfo, err
	}

	revocationInfo.Certs, _ = getRevocationInfoCertObj(pdfContext, dict, "Cert")
	revocationInfo.OCSPS, _ = getRevocationInfoOCSPSObj(pdfContext, dict, "OCSP")
	revocationInfo.CRLS, _ = getRevocationInfoCRLSObj(pdfContext, dict, "CRL")

	if len(revocationInfo.Certs) > 0 || len(revocationInfo.OCSPS) > 0 || len(revocationInfo.CRLS) > 0 {
		return true, revocationInfo, nil
	}

	return false, revocationInfo, nil
}

func getRevocationInfoCertObj(pdfContext *pdfcpu.Context, dict pdfcpu.Dict, certKey string) ([]*x509.Certificate, error) {
	// Find Certs object
	certsObj, found := dict.Find(certKey)
	if !found {
		return nil, nil
	}

	// Certs object is an indirect object pointing to an array
	certsArray, err := pdfContext.DereferenceArray(certsObj)
	if err != nil {
		return nil, err
	}

	certsBytes := make([][]byte, len(certsArray))
	for i, certsArrayElement := range certsArray {
		arrayElement := certsArrayElement.(pdfcpu.IndirectRef)
		certByte, _, err := pdfContext.DereferenceStreamDict(arrayElement)
		if err != nil {
			return nil, err
		}

		err = certByte.Decode()
		if err != nil {
			return nil, err
		}

		certsBytes[i] = certByte.Content
	}

	// Create array of certificates
	certs := make([]*x509.Certificate, len(certsBytes))

	// Each certificate object is an ASN.1 encoded x509 certificate
	for i, certStream := range certsBytes {
		// Parse certificate
		cert, err := x509.ParseCertificate(certStream)
		if err != nil {
			return nil, err
		}

		// Include parsed ocsp in ocsp array
		certs[i] = cert
	}

	return certs, nil
}

func getRevocationInfoOCSPSObj(pdfContext *pdfcpu.Context, dict pdfcpu.Dict, ocspKey string) ([]*ocsp.Response, error) {
	// Access OCSPs object
	ocspsObj, found := dict.Find(ocspKey)
	if !found {
		return nil, nil
	}

	// OCSPs object is an indirect object pointing to an array
	ocspsArray, err := pdfContext.DereferenceArray(ocspsObj)
	if err != nil {
		return nil, err
	}

	ocspsBytes := make([][]byte, len(ocspsArray))

	// Iterate through the ocsp list
	for i, ocspArrayElement := range ocspsArray {
		// Each element on the array is an indirect object pointing to the OCSP stream dictionary
		arrayElement := ocspArrayElement.(pdfcpu.IndirectRef)
		ocspByte, _, err := pdfContext.DereferenceStreamDict(arrayElement)
		if err != nil {
			return nil, err
		}

		err = ocspByte.Decode()
		if err != nil {
			return nil, err
		}

		ocspsBytes[i] = ocspByte.Content
	}

	// Create array of ocsp responses
	ocsps := make([]*ocsp.Response, len(ocspsBytes))

	// Each OCSP object is an ASN.1 encoded OCSP response
	for i, ocspStream := range ocspsBytes {
		// Parse OCSP response
		ocspResponse, err := ocsp.ParseResponse(ocspStream, nil)
		if err != nil {
			return nil, err
		}

		// Include parsed ocsp in ocsp array
		ocsps[i] = ocspResponse
	}

	return ocsps, nil
}

func getRevocationInfoCRLSObj(pdfContext *pdfcpu.Context, dict pdfcpu.Dict, certKey string) ([]*pkix.CertificateList, error) {
	// Find Certs object
	crlsObj, found := dict.Find(certKey)
	if !found {
		return nil, nil
	}

	// Certs object is an indirect object pointing to an array
	crlsArray, err := pdfContext.DereferenceArray(crlsObj)
	if err != nil {
		return nil, err
	}

	crlsBytes := make([][]byte, len(crlsArray))
	for i, crlsArrayElement := range crlsArray {
		arrayElement := crlsArrayElement.(pdfcpu.IndirectRef)
		certByte, _, err := pdfContext.DereferenceStreamDict(arrayElement)
		if err != nil {
			return nil, err
		}

		err = certByte.Decode()
		if err != nil {
			return nil, err
		}

		crlsBytes[i] = certByte.Content
	}

	// Create array of certificates
	crls := make([]*pkix.CertificateList, len(crlsBytes))

	// Each certificate object is an ASN.1 encoded x509 certificate
	for i, certStream := range crlsBytes {
		// Parse certificate
		cert, err := x509.ParseCRL(certStream)
		if err != nil {
			return nil, err
		}

		// Include parsed ocsp in ocsp array
		crls[i] = cert
	}

	return crls, nil
}

func getDigestAlgorithmFromOid(oid asn1.ObjectIdentifier) (*crypto.Hash, error) {
	for alg, algOid := range hashOIDs {
		if algOid.Equal(oid) {
			return &alg, nil
		}
	}

	return nil, errors.New("digest algorithm oid unknown")
}

// IsPDFCertified is a method to check pdf is certified
func (p Signatures) IsPDFCertified() bool {
	for _, sig := range p {
		if sig.Type == TypeCertified {
			return true
		}
	}

	return false
}
