package license

type ContentKey struct {
	KeyIdLen uint8   // length of a key identifier
	KeyId    []uint8 // key identifier with length of KeyIdLen bytes
}

type Content struct {
	UnitHeader
	Length uint16 // length of data
	// It can be UUID or whatever is unique.
	ContentId uint64       // content identifier
	Keys      []ContentKey // at least one key

	// There can be other fields about one content or asset.
}

type ChinaDrmLicense struct {
	CommonLicense
	Content Content
}

func (this *ChinaDrmLicense) Serialize() []byte {
	return []byte("")
}
