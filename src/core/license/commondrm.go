/*
	Opendrm, an open source implementation of industry-grade DRM
	(Digital Rights Management) or Key System.
	Copyright (C) 2018  wilkk

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

/*
	This implementation of common license is based upon GY-T 277-2014 互联网电视数字版权管理技术规范.
*/
package license

import (
	"bytes"
	"core/key"
	"encoding/base64"
	"encoding/binary"
	"time"
)

/*
	CommonLicense contains the basic information that a license functions upon.
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
)

type CommonLicense struct {
	Header    LicenseHeader
	Keys      Keys
	Objects   AuthObjects
	Rights    Rights
	Policys   Policys // Usage rules of Rights
	Counter   Counter
	Signature Signature
}

// Currently we don't use Counter Unit.
func NewCommonLicense(kids []string, objIds []string, certId string) *CommonLicense {
	units := len(kids)*2 + len(objIds) + 1

	keys := Keys{}
	keygen := key.NewKeyGenerator(nil)
	for _, kid := range kids {
		key := keygen.GenKeyByDefaultSeed(kid)
		keys = append(keys, NewKey(kid, key))
	}

	objs := AuthObjects{}
	for _, objId := range objIds {
		objs = append(objs, NewAuthObject(authObjTypeAccount, objId))
	}

	plcs := Policys{}
	for _, kid := range kids {
		plcs = append(plcs, NewPolicy(kid))
	}

	rs := Rights{}
	rs = append(rs, NewRight(rightsTypePlay, nil))

	return &CommonLicense{
		Header:    newLicenseHeader(1, 1234567890, uint8(units)),
		Rights:    rs,
		Objects:   objs,
		Policys:   plcs,
		Keys:      keys,
		Counter:   NewCounter(ctrTypeAnd),
		Signature: newSignature(certId),
	}
}

func (cl *CommonLicense) Serialize(withCnt, withSig bool) []byte {
	buff := &bytes.Buffer{}
	binary.Write(buff, binary.BigEndian, cl.Header)
	binary.Write(buff, binary.BigEndian, cl.Keys.Bytes())
	binary.Write(buff, binary.BigEndian, cl.Objects.Bytes())
	binary.Write(buff, binary.BigEndian, cl.Rights.Bytes())
	binary.Write(buff, binary.BigEndian, cl.Policys.Bytes())
	if withCnt {
		binary.Write(buff, binary.BigEndian, cl.Counter.Bytes())
	}

	if withSig {
		binary.Write(buff, binary.BigEndian, cl.Signature.Bytes())
	}

	return buff.Bytes()
}

func (cl *CommonLicense) Sign(withCnt bool) error {
	bytes := cl.Serialize(withCnt, false)

	sig, err := Sign(bytes)
	if err != nil {
		return err
	}

	cl.Signature.SignatureData = sig
	cl.Signature.SignatureLen = uint16(len(sig))

	return nil
}

func (cl *CommonLicense) Base64String() string {
	return base64.StdEncoding.EncodeToString(cl.Serialize(false, true))
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

const (
	authObjTypeAccount = 0x01
	authObjTypeDevice  = 0x02
	authObjTypeIp      = 0x03
)

type AuthObject struct {
	UnitHeader

	ObjectType uint8  // object type
	ObjectId   []byte // object id, like user account id, device id or others similar.
}

func NewAuthObject(objType uint8, objId string) AuthObject {
	return AuthObject{
		UnitHeader: UnitHeader{
			Type:   0x02,
			Index:  0x01,
			Length: uint16(1 + len(objId)),
		},
		ObjectType: objType,
		ObjectId:   []byte(objId),
	}
}

func (ao *AuthObject) Bytes() []byte {
	buff := &bytes.Buffer{}

	binary.Write(buff, binary.BigEndian, ao.Type)
	binary.Write(buff, binary.BigEndian, ao.Index)
	binary.Write(buff, binary.BigEndian, ao.Length)
	binary.Write(buff, binary.BigEndian, ao.ObjectType)
	binary.Write(buff, binary.BigEndian, ao.ObjectId)

	return buff.Bytes()
}

type AuthObjects []AuthObject

func (aos *AuthObjects) Bytes() []byte {
	buff := &bytes.Buffer{}
	for _, obj := range *aos {
		buff.Write(obj.Bytes())
	}
	return buff.Bytes()
}

// The keys is issued in encrypted form.
type Key struct {
	UnitHeader

	AlgorithmId uint8  // encryption algorithm of the key
	KeyDataLen  uint16 // encrypted key data length
	KeyData     []byte // encrypted key data with length of KeyDataLen bytes

	// Auxiliary info of key. This is judged by Length field of UnitHeader.
	KeyType  uint8  // key type
	KeyIdLen uint8  // length of KeyId
	KeyId    []byte // KeyId data
	/*
		UpperKeyType  uint8  // type of the key that is used to encrypt key
		UpperKeyIdLen uint8  // length of UpperKeyId
		UpperKeyId    []byte // id of the key that is used to encrypt key
	*/
}

func NewKey(kid string, key []byte) Key {
	return Key{
		UnitHeader: UnitHeader{
			Type:  0x03,
			Index: 0x01,
		},
		AlgorithmId: algorithmBlockCipher_AES_128_128,
		KeyData:     key,
		KeyDataLen:  uint16(len(key)),
		KeyType:     keyTypeContent,
		KeyIdLen:    uint8(len(kid)),
		KeyId:       []byte(kid),
	}
}

func (k *Key) Bytes() []byte {
	buff := &bytes.Buffer{}

	binary.Write(buff, binary.BigEndian, k.Type)
	binary.Write(buff, binary.BigEndian, k.Index)
	binary.Write(buff, binary.BigEndian, k.Length)
	binary.Write(buff, binary.BigEndian, k.AlgorithmId)
	binary.Write(buff, binary.BigEndian, k.KeyDataLen)
	binary.Write(buff, binary.BigEndian, k.KeyData)

	return buff.Bytes()
}

type Keys []Key

func (ks *Keys) Bytes() []byte {
	buff := &bytes.Buffer{}
	for _, k := range *ks {
		buff.Write(k.Bytes())
	}
	return buff.Bytes()
}

// Concrete data of each kind of key rule, like play times if rule type is play.
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

// Restrictions of rights
type Policy struct {
	UnitHeader

	KeyType     uint8    // key type
	KeyIdLen    uint8    // length of KeyId
	KeyId       []byte   // KeyId data
	KeyRulesNum uint8    // number of key rules
	KeyRules    KeyRules // key rules data
}

func NewPolicy(kid string) Policy {
	now := time.Now()
	startTime := now.Unix()
	endTime := now.AddDate(1, 0, 1).Unix()
	buff := &bytes.Buffer{}
	binary.Write(buff, binary.BigEndian, startTime)
	startTimeData := buff.Bytes()
	buff.Reset()
	binary.Write(buff, binary.BigEndian, endTime)
	endTimeData := buff.Bytes()

	plc := Policy{
		UnitHeader: UnitHeader{
			Type:  0x04,
			Index: 0x01,
		},
		KeyType:     keyTypeContent,
		KeyIdLen:    uint8(len(kid)),
		KeyId:       []byte(kid),
		KeyRulesNum: 1,
		KeyRules: KeyRules{
			KeyRule{
				KeyRuleType: keyRuleTypeStartTime,
				KeyRuleLen:  uint8(len(startTimeData)),
				KeyRuleData: startTimeData,
			},
			KeyRule{
				KeyRuleType: keyRuleTypeEndTime,
				KeyRuleLen:  uint8(len(endTimeData)),
				KeyRuleData: endTimeData,
			},
		},
	}
	plc.Length = uint16(len(plc.Bytes()) - 2)

	return plc
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

type Policys []Policy

func (ps *Policys) Bytes() []byte {
	buff := &bytes.Buffer{}
	for _, p := range *ps {
		buff.Write(p.Bytes())
	}
	return buff.Bytes()
}

const (
	rightsTypePlay       = 0x10
	rightsTypeRecord     = 0x20
	rightsTypeCopy       = 0x30
	rightsTypeStore      = 0x40
	rightsTypeForward    = 0x50
	rightsTypeExecute    = 0x60
	rightsTypeSuperRight = 0x80
)

/*
	Rights include Play, Record, Copy, Store, Forward, Execute or SuperRight(all rights).
	Right Type and data format are as below:
	+-----------------------------------------------------------------------------------+
	|     Right Type   			|	Code    |		Data								|
	|-----------------------------------------------------------------------------------|
	|	play					|   0x10	|   	nil									|
	|   play by times			|   0x11	|   	uint32								|
	|   play by time			|   0x12	|   	uint32(in seconds)					|
	|   play by time interval	|   0x13	|   	uint32(start time)|uint32(end time)	|
	|-----------------------------------------------------------------------------------|
	|	record					|   0x20	|   	nil									|
	|   record by time interval	|   0x21	|   	uint32(start time)|uint32(end time)	|
	|   record by time 			|   0x22	|   	uint32(in seconds)					|
	|-----------------------------------------------------------------------------------|
	|	copy					|   0x30	|		nil									|
	|-----------------------------------------------------------------------------------|
	|	store					|   0x40	|		nil									|
	|-----------------------------------------------------------------------------------|
	|	forward					|   0x50	|		nil									|
	|-----------------------------------------------------------------------------------|
	|	execute					|   0x60	|		nil									|
	|-----------------------------------------------------------------------------------|
	|	super right				|   0x80	|		nil									|
	+-----------------------------------------------------------------------------------+
*/
type Right struct {
	UnitHeader

	RightData []byte
}

func NewRight(rType uint8, data []byte) Right {
	return Right{
		UnitHeader: UnitHeader{
			Type:   rType,
			Index:  0x01,
			Length: uint16(len(data)),
		},
		RightData: data,
	}
}

func (r *Right) Bytes() []byte {
	buff := &bytes.Buffer{}

	binary.Write(buff, binary.BigEndian, r.Type)
	binary.Write(buff, binary.BigEndian, r.Index)
	binary.Write(buff, binary.BigEndian, r.Length)
	binary.Write(buff, binary.BigEndian, r.RightData)

	return buff.Bytes()
}

type Rights []Right

func (rs *Rights) Bytes() []byte {
	buff := &bytes.Buffer{}
	for _, r := range *rs {
		buff.Write(r.Bytes())
	}
	return buff.Bytes()
}

const (
	ctrTypeAnd = 0xA0
	ctrTypeOr  = 0xA1
	ctrTypeNot = 0xA2
	ctrTypeXor = 0xA3
)

// This Unit indicates the relationships between multiple Right Units. It could be 'and', 'or', 'not' and 'xor'.
// If this unit is not ever used, 'and' is the default relationship of all basic units.
type Counter struct {
	UnitHeader

	RightsIndexNum uint16
	RightsIndex    []uint8
}

func NewCounter(uType uint8) Counter {
	return Counter{
		UnitHeader: UnitHeader{
			Type:   uType,
			Index:  0x01,
			Length: 4,
		},
		RightsIndexNum: 0,
	}
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

func newSignature(certId string) Signature {
	return Signature{
		UnitHeader: UnitHeader{
			Type:  0xFF,
			Index: 0x01,
		},
		AlgorithmId:     algorithmSignature_RSA_SHA1_1024,
		CertificatId:    []byte(certId),
		CertificatIdLen: uint8(len([]byte(certId))),
	}
}
