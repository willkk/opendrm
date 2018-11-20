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

package license

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
)

type ContentKey struct {
	KeyIdLen uint8  // length of a key identifier
	KeyId    []byte // key identifier with length of KeyIdLen bytes
}

type ContentKeys []ContentKey

func (cks *ContentKeys) Bytes() []byte {
	buff := &bytes.Buffer{}

	for _, ck := range *cks {
		binary.Write(buff, binary.BigEndian, ck.KeyIdLen)
		binary.Write(buff, binary.BigEndian, ck.KeyId)
	}

	return buff.Bytes()
}

type Content struct {
	UnitHeader
	// It can be UUID or whatever is unique.
	ContentId uint64      // content identifier
	Keys      ContentKeys // at least one key

	// There can be other fields about content or asset.
}

func (c *Content) Bytes() []byte {
	buff := &bytes.Buffer{}

	binary.Write(buff, binary.BigEndian, c.Type)
	binary.Write(buff, binary.BigEndian, c.Index)
	binary.Write(buff, binary.BigEndian, c.Length)
	binary.Write(buff, binary.BigEndian, c.ContentId)
	binary.Write(buff, binary.BigEndian, c.Keys.Bytes())

	return buff.Bytes()
}

func NewContent(cid uint64, kids []string) *Content {
	keys := ContentKeys{}
	for _, kid := range kids {
		keys = append(keys, ContentKey{
			KeyIdLen: uint8(len([]byte(kid))),
			KeyId:    []byte(kid),
		})
	}
	return &Content{
		UnitHeader: UnitHeader{
			Type:  0x01,
			Index: 0x01,
		},
		ContentId: cid,
		Keys:      keys,
	}
}

type ChinaDrmLicense struct {
	CommonLicense
	Content Content
}

func NewChinaDrmLicense(cid uint64, kids []string, objIds []string, certId string) ChinaDrmLicense {
	return ChinaDrmLicense{
		CommonLicense: *NewCommonLicense(kids, objIds, certId),
		Content:       *NewContent(cid, kids),
	}
}

func (cdl *ChinaDrmLicense) Serialize(withCnt, withSig bool) []byte {
	comnBytes := cdl.CommonLicense.Serialize(false, false)

	buff := &bytes.Buffer{}
	binary.Write(buff, binary.BigEndian, comnBytes)
	binary.Write(buff, binary.BigEndian, cdl.Content.Bytes())

	if withSig {
		binary.Write(buff, binary.BigEndian, cdl.Signature.Bytes())
	}

	return buff.Bytes()
}

func (cdl *ChinaDrmLicense) Sign(withCnt bool) error {
	bytes := cdl.Serialize(withCnt, false)
	sig, err := Sign(bytes)
	if err != nil {
		return err
	}

	cdl.Signature.SignatureData = sig
	cdl.Signature.SignatureLen = uint16(len(sig))

	return nil
}

func (cdl *ChinaDrmLicense) Base64String() string {
	return base64.StdEncoding.EncodeToString(cdl.Serialize(false, true))
}
