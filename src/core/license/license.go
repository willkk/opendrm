package license

const (
	licenseTypeCommon = iota
	licenseTypeChinaDrm
	licenseTypePlayReady
	licenseTypeWidevine
)

type License interface {
	Serialize() []byte
}
