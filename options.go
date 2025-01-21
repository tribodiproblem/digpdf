package digpdf

// Option return PDFWatermark with Option.
type Option func(signature *PDFSignature)

// WithPassword is a function uses to set user password.
func WithPassword(password string) Option {
	return func(p *PDFSignature) {
		configuration := p.configuration
		configuration.UserPW = password
		p.configuration = configuration
	}
}

// WithMetadata is a function uses to set metadata.
func WithMetadata(metadata *Metadata) Option {
	return func(p *PDFSignature) {
		p.metadata = metadata
	}
}

// WithCertificateInfo is a function uses to set certificateInfo.
func WithCertificateInfo() Option {
	return func(p *PDFSignature) {
		p.certificateInfo = true
	}
}
