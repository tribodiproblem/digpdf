package digremover

import (
	"github.com/tribodiproblem/fvckpdf/pkg/api"
	"github.com/tribodiproblem/fvckpdf/pkg/pdfcpu"
)

// WritePDF is a function uses to write pdfcpu.Context into PDF file.
func WritePDF(pdfContext *pdfcpu.Context, outputFilePath string, conf *pdfcpu.Configuration, md *Metadata) (bool, error) {
	// write current state to temp PDF file
	errWriteOutputPDF := api.WriteContextFile(pdfContext, outputFilePath)
	if errWriteOutputPDF != nil {
		return false, errWriteOutputPDF
	}

	return true, nil
}
