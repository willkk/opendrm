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

package key

import "testing"

func TestGenerateKeyAndKid(t *testing.T) {
	keyGen := NewKeyGenerator(nil)
	key, kid := keyGen.GenRandKey()
	t.Logf("key:%x, kid:%s", key, kid)
}

func TestGenerateKeyAndKidBySeed(t *testing.T) {
	kid := "3bff1f0c-0b16-4641-84af-8832f1cd37b5"
	keyGen := NewKeyGenerator(defaultKeySeed)
	ck := keyGen.GenKeyBySeed(kid)
	t.Logf("key:%x", ck)
}
