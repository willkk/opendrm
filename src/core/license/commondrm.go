/*
	This implementation of common license is baseo upon GY-T 277-2014 互联网电视数字版权管理技术规范.
*/
package license

import (
	"bytes"
	"encoding/binary"
	"log"
)

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

type CommonLicense struct {
	Header    LicenseHeader
	Keys      Keys
	Objects   AuthObjects
	Rights    Rights
	Policy    Policy // Usage rules of Rights
	Counter   Counter
	Signature Signature
}

func (cl *CommonLicense) Serialize() []byte {
	buff := &bytes.Buffer{}
	binary.Write(buff, binary.BigEndian, cl.Header)
	log.Printf("after hdr len: %d", buff.Len())
	binary.Write(buff, binary.BigEndian, cl.Keys.Bytes())
	log.Printf("after kys len: %d", buff.Len())
	binary.Write(buff, binary.BigEndian, cl.Objects.Bytes())
	log.Printf("after objs len: %d", buff.Len())
	binary.Write(buff, binary.BigEndian, cl.Rights.Bytes())
	log.Printf("after rgts len: %d", buff.Len())
	binary.Write(buff, binary.BigEndian, cl.Policy.Bytes())
	log.Printf("after pcy len: %d", buff.Len())
	binary.Write(buff, binary.BigEndian, cl.Counter.Bytes())
	log.Printf("after cnt len: %d", buff.Len())
	binary.Write(buff, binary.BigEndian, cl.Signature.Bytes())
	log.Printf("after sgt len: %d", buff.Len())

	return buff.Bytes()
}

func NewCommonLicense(kids []string) *CommonLicense {
	units := len(kids) + 5
	return &CommonLicense{
		Header:    newLicenseHeader(1, 1234567890, uint8(units)),
		Signature: newSignature(),
	}
}

type UnitHeader struct {
	Type   uint8
	Index  uint8
	Length uint16 // length of data, in bytes
}

// type 0x00
type LicenseHeader struct {
	UnitHeader

	Version  uint8  // license version, currently is 1.
	Id       uint64 // license id
	UnitsNum uint8  // number of basic units
}

func newLicenseHeader(ver uint8, id uint64, units uint8) LicenseHeader {
	return LicenseHeader{
		UnitHeader: UnitHeader{
			Type:   0x00,
			Index:  0x00,
			Length: 10,
		},
		Version:  ver,
		Id:       id,
		UnitsNum: units,
	}
}

type AuthObjects struct {
	UnitHeader

	ObjectType uint8  // object type
	ObjectId   []byte // object id, like user account id, device id or others similar.
}

func (ao *AuthObjects) Bytes() []byte {
	buff := &bytes.Buffer{}

	binary.Write(buff, binary.BigEndian, ao.Type)
	binary.Write(buff, binary.BigEndian, ao.Index)
	binary.Write(buff, binary.BigEndian, ao.Length)
	binary.Write(buff, binary.BigEndian, ao.ObjectType)
	binary.Write(buff, binary.BigEndian, ao.ObjectId)

	return buff.Bytes()
}

// The keys is issued in encrypted form.
type Keys struct {
	UnitHeader

	AlgorithmId uint8  // encryption algorithm of the key
	KeyDataLen  uint16 // encrypted key data length
	KeyData     []byte // encrypted key data with length of KeyDataLen bytes

	// Auxiliary info of key. This is judged by Length field of UnitHeader.
	/*	KeyType       uint8  // key type
		KeyIdLen      uint8  // length of KeyId
		KeyId         []byte // KeyId data
		UpperKeyType  uint8  // type of the key that is used to encrypt key
		UpperKeyIdLen uint8  // length of UpperKeyId
		UpperKeyId    []byte // id of the key that is used to encrypt key
	*/
}

func (k *Keys) Bytes() []byte {
	buff := &bytes.Buffer{}

	binary.Write(buff, binary.BigEndian, k.Type)
	binary.Write(buff, binary.BigEndian, k.Index)
	binary.Write(buff, binary.BigEndian, k.Length)
	binary.Write(buff, binary.BigEndian, k.AlgorithmId)
	binary.Write(buff, binary.BigEndian, k.KeyDataLen)
	binary.Write(buff, binary.BigEndian, k.KeyData)

	return buff.Bytes()
}

type KeyRule struct {
	KeyRuleType uint8
	KeyRuleLen  uint8
	KeyRuleData []byte
}

type KeyRules []KeyRule

func (krs *KeyRules) Bytes() []byte {
	buff := &bytes.Buffer{}
	for _, kr := range *krs {
		binary.Write(buff, binary.BigEndian, kr.KeyRuleType)
		binary.Write(buff, binary.BigEndian, kr.KeyRuleLen)
		binary.Write(buff, binary.BigEndian, kr.KeyRuleData)
	}

	return buff.Bytes()
}

// Policy of keys, or key rules
type Policy struct {
	UnitHeader

	KeyType     uint8     // key type
	KeyIdLen    uint8     // length of KeyId
	KeyId       []byte    // KeyId data
	KeyRulesNum uint8     // number of key rules
	KeyRules    KeyRules // key rules data
}

func (p *Policy) Bytes() []byte {
	buff := &bytes.Buffer{}

	binary.Write(buff, binary.BigEndian, p.Type)
	binary.Write(buff, binary.BigEndian, p.Index)
	binary.Write(buff, binary.BigEndian, p.Length)
	binary.Write(buff, binary.BigEndian, p.KeyType)
	binary.Write(buff, binary.BigEndian, p.KeyIdLen)
	binary.Write(buff, binary.BigEndian, p.KeyId)
	binary.Write(buff, binary.BigEndian, p.KeyRulesNum)
	binary.Write(buff, binary.BigEndian, p.KeyRules.Bytes())

	return buff.Bytes()
}

type Rights struct {
	UnitHeader

	RightsData []byte
}

func (r *Rights) Bytes() []byte {
	buff := &bytes.Buffer{}

	binary.Write(buff, binary.BigEndian, r.Type)
	binary.Write(buff, binary.BigEndian, r.Index)
	binary.Write(buff, binary.BigEndian, r.Length)
	binary.Write(buff, binary.BigEndian, r.RightsData)

	return buff.Bytes()
}

type Counter struct {
	UnitHeader

	RightsIndexNum uint16
	RightsIndex    []uint8
}

func (c *Counter) Bytes() []byte {
	buff := &bytes.Buffer{}

	binary.Write(buff, binary.BigEndian, c.Type)
	binary.Write(buff, binary.BigEndian, c.Index)
	binary.Write(buff, binary.BigEndian, c.Length)
	binary.Write(buff, binary.BigEndian, c.RightsIndexNum)
	binary.Write(buff, binary.BigEndian, c.RightsIndex)

	return buff.Bytes()
}

type Signature struct {
	UnitHeader

	AlgorithmId     uint8
	CertificatIdLen uint8
	CertificatId    []byte
	SignatureLen    uint16
	SignatureData   []byte
}

func (s *Signature) Bytes() []byte {
	buff := &bytes.Buffer{}

	binary.Write(buff, binary.BigEndian, s.Type)
	binary.Write(buff, binary.BigEndian, s.Index)
	binary.Write(buff, binary.BigEndian, s.Length)
	binary.Write(buff, binary.BigEndian, s.AlgorithmId)
	binary.Write(buff, binary.BigEndian, s.CertificatIdLen)
	binary.Write(buff, binary.BigEndian, s.CertificatId)
	binary.Write(buff, binary.BigEndian, s.SignatureLen)
	binary.Write(buff, binary.BigEndian, s.SignatureData)

	return buff.Bytes()
}

func newSignature() Signature {
	return Signature{
		UnitHeader: UnitHeader{
			Type:  0xFF,
			Index: 0x01,
		},
		AlgorithmId: algorithmBlockCipher_AES_128_128,
	}
}
