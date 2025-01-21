package digremover_test

import (
	"testing"

	digremover "github.com/tribodiproblem/digpdf"

	"github.com/stretchr/testify/assert"
)

func TestDigRemover(t *testing.T) {
	t.Run("in1, it should not ok", func(t *testing.T) {
		inputFile := digremover.CurrentDir() + "/in1.pdf"
		outputFile := digremover.CurrentDir() + "/out1.pdf"
		pdfSignature := digremover.New(inputFile,
			digremover.WithCertificateInfo(),
		)

		_, err := pdfSignature.RemoveDigitalSignatures(outputFile)
		assert.Error(t, err)
	})

	t.Run("in2, it should ok", func(t *testing.T) {
		inputFile := digremover.CurrentDir() + "/in2.pdf"
		outputFile := digremover.CurrentDir() + "/out2.pdf"
		pdfSignature := digremover.New(inputFile,
			digremover.WithCertificateInfo(),
		)

		_, err := pdfSignature.RemoveDigitalSignatures(outputFile)
		assert.NoError(t, err)
	})

	t.Run("in3, it should ok", func(t *testing.T) {
		inputFile := digremover.CurrentDir() + "/in3.pdf"
		outputFile := digremover.CurrentDir() + "/out3.pdf"
		pdfSignature := digremover.New(inputFile,
			digremover.WithCertificateInfo(),
		)

		_, err := pdfSignature.RemoveDigitalSignatures(outputFile)
		assert.NoError(t, err)
	})

	t.Run("in4, it should ok", func(t *testing.T) {
		inputFile := digremover.CurrentDir() + "/in4.pdf"
		outputFile := digremover.CurrentDir() + "/out4.pdf"
		pdfSignature := digremover.New(inputFile,
			digremover.WithCertificateInfo(),
		)

		_, err := pdfSignature.RemoveDigitalSignatures(outputFile)
		assert.NoError(t, err)
	})

	t.Run("in5, it should ok", func(t *testing.T) {
		inputFile := digremover.CurrentDir() + "/in5.pdf"
		outputFile := digremover.CurrentDir() + "/out5.pdf"
		pdfSignature := digremover.New(inputFile,
			digremover.WithCertificateInfo(),
		)

		_, err := pdfSignature.RemoveDigitalSignatures(outputFile)
		assert.NoError(t, err)
	})
}
