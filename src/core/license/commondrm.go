/*
	This implementation of common license is baseo upon GY-T 277-2014 互联网电视数字版权管理技术规范.
*/
package license

/*  CommonLicense contains the basic information that a license functions upon.
A common license struct is as below:
+-----------------------------------+
|									|
|			License Header			|
|									|
|-----------------------------------|
|				Content				|
|-----------------------------------|
|			Authorized Objects		|
|-----------------------------------|
|				Rights				|
|-----------------------------------|
|				Keys				|
|-----------------------------------|
|				Policy				|
|-----------------------------------|
|				Counter				|
|-----------------------------------|
|				Signature			|
+-----------------------------------+

The binary form of license is as below:
+--------------------------------------------------------------------------+
| license hdr(basic unit) | basic unit | basic unit | ... | signature unit |
+--------------------------------------------------------------------------+
The sequence of intermediate basic units could be changed at will.

Basic unit struct is as below:
+-----------------------------------------------------------------+
| 		Unit Type(16 bits)     | Length(16 bits) | Data(Nx8 bits) |
|-----------------------------------------------------------------|
| type(8 bits) | index(8 bits) |    len          |  data 		  |
+-----------------------------------------------------------------+

The following is the whole values of Unit Type:
+-----------------------------------------------------------+
|		  Type			|  Unit Type Value					|
|-----------------------------------------------------------|
|	  License Header	|				0x00				|
|		Content			|				0x01				|
|	Authorized Objects	|				0x02				|
|		 Keys			|				0x03				|
|		Policy			|				0x04				|
|		Rights			|	  		0x10 ~ 0x9F				|
|		Counter			|	  		0xA0 ~ 0xAF				|
|		Signature		|				0xFF				|
|		Reserved		|  0x05~0x0F, 0xD0~0xDF, 0xE0~0xEF	|
+-----------------------------------------------------------+

*/
type CommonLicense struct {
	Header  LicenseHeader
	Objects AuthObjects
	Rights  Rights
	Policy  Policy // Usage rules of Rights
	Counter Counter
}

func (this *CommonLicense) Serialize() []byte {

	return []byte("")
}

type UnitHeader struct {
	Type   uint8
	Index  uint8
	Length uint16 // length of data
}

type LicenseHeader struct {
	UnitHeader

	Version  uint8  // license version, currently is 1.
	Id       uint64 // license id
	UnitsNum uint8  // number of basic units
}

type AuthObjects struct {
	UnitHeader

	Length     uint16 // length of data
	ObjectType uint8  // object type
	ObjectId   []byte // object id, like user account id, device id or others similar.
}

const (
	keyTypeContent  = 0x01
	keyTypeBusiness = 0x02
	keyTypeDevice   = 0x03

	algorithmHash_SHA_1              = 0x00
	algorithmHash_SHA_256            = 0x01
	algorithmHash_SM3_256            = 0x02
	algorithmPubKey_RSA_1024         = 0x10
	algorithmPubKey_RSA_2048         = 0x11
	algorithmPubKey_SM2_256          = 0x12
	algorithmBlockCipher_AES_128_128 = 0x20
	algorithmBlockCipher_3DES_64_112 = 0x21
	algorithmBlockCipher_SM4_128     = 0x22
	algorithmStreamCipher_RC4        = 0x30
	algorithmSignature_RSA_SHA1_1024 = 0x40
	algorithmSignature_RSA_SHA1_2048 = 0x41
	algorithmSignature_SM2_256       = 0x42

	keyRuleTypeStartTime    = 0x01 // uint32, the seconds since 1970-01-01 00:00:00
	keyRuleTypeEndTime      = 0x02 // uint32, the seconds since 1970-01-01 00:00:00
	keyRuleTypePlayTimes    = 0x03 // uint32, times that this content can be used
	keyRuleTypeTimeSpan     = 0x04 // uint32, seconds since license is first used
	keyRuleTypeAccuTimeSpan = 0x05 // uint32, all seconds that license is allowed to be used

	counterTypeAnd = 0xA0
	counterTypeOr  = 0xA1
	counterTypeNot = 0xA2
	counterTypeXor = 0xA3
)

// The keys is issued in encrypted form.
type Keys struct {
	UnitHeader

	AlgorithmId   uint8  // encryption algorithm of the key
	KeyDataLen    uint16 // encrypted key data length
	KeyData       []byte // encrypted key data with length of KeyDataLen bytes
	KeyType       uint8  // key type
	KeyIdLen      uint8  // length of KeyId
	KeyId         []byte // KeyId data
	UpperKeyType  uint8  // type of the key that is used to encrypt key
	UpperKeyIdLen uint8  // length of UpperKeyId
	UpperKeyId    []byte // id of the key that is used to encrypt key
}

type KeyRule struct {
	KeyRuleType uint8
	KeyRuleLen  uint8
	KeyRuleData []byte
}

// Policy of keys, or key rules
type Policy struct {
	UnitHeader

	KeyType     uint8     // key type
	KeyIdLen    uint8     // length of KeyId
	KeyId       []byte    // KeyId data
	KeyRulesNum uint8     // number of key rules
	KeyRules    []KeyRule // key rules data
}

type Rights struct {
	UnitHeader

	RightsData []byte
}

type Counter struct {
	UnitHeader

	RightsIndexNum uint16
	RightsIndex    []uint8
}

type Signature struct {
	UnitHeader

	AlgorithmId     uint8
	CertificatIdLen uint8
	CertificatId    []byte
	SignatureLen    uint16
	SignatureData   []byte
}
