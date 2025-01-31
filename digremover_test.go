package digpdf_test

import (
	"testing"

	digpdf "github.com/tribodiproblem/digpdf"

	"github.com/stretchr/testify/assert"
)

func TestDigRemover(t *testing.T) {
	t.Run("in1, it should not ok", func(t *testing.T) {
		inputFile := digpdf.CurrentDir() + "/testseal.pdf"
		outputFile := digpdf.CurrentDir() + "/testsealout.pdf"
		pdfSignature := digpdf.New(inputFile,
			digpdf.WithCertificateInfo(),
		)

		_, err := pdfSignature.RemoveDigitalSignatures(outputFile)
		assert.NoError(t, err)
	})

	t.Run("in2, it should ok", func(t *testing.T) {
		inputFile := digpdf.CurrentDir() + "/in2.pdf"
		outputFile := digpdf.CurrentDir() + "/out2.pdf"
		pdfSignature := digpdf.New(inputFile,
			digpdf.WithCertificateInfo(),
		)

		_, err := pdfSignature.RemoveDigitalSignatures(outputFile)
		assert.NoError(t, err)
	})

	t.Run("in3, it should ok", func(t *testing.T) {
		inputFile := digpdf.CurrentDir() + "/in3.pdf"
		outputFile := digpdf.CurrentDir() + "/out3.pdf"
		pdfSignature := digpdf.New(inputFile,
			digpdf.WithCertificateInfo(),
		)

		_, err := pdfSignature.RemoveDigitalSignatures(outputFile)
		assert.NoError(t, err)
	})

	t.Run("in4, it should ok", func(t *testing.T) {
		inputFile := digpdf.CurrentDir() + "/in4.pdf"
		outputFile := digpdf.CurrentDir() + "/out4.pdf"
		pdfSignature := digpdf.New(inputFile,
			digpdf.WithCertificateInfo(),
		)

		_, err := pdfSignature.RemoveDigitalSignatures(outputFile)
		assert.NoError(t, err)
	})

	t.Run("in5, it should ok", func(t *testing.T) {
		inputFile := digpdf.CurrentDir() + "/in5.pdf"
		outputFile := digpdf.CurrentDir() + "/out5.pdf"
		pdfSignature := digpdf.New(inputFile,
			digpdf.WithCertificateInfo(),
		)

		_, err := pdfSignature.RemoveDigitalSignatures(outputFile)
		assert.NoError(t, err)
	})
}
