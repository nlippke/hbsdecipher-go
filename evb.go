package main

import "hash"

/*
 * EVPBytesToKey converts info to EVP BytesToKey format used by OpenSSL.
 * Thanks go to Ola Bini for releasing this source on his blog. The source was
 * obtained from http://olabini.com/blog/tag/evp_bytestokey/.
 * .
 */
func EVPBytesToKey(keyLen int, ivLen int, md hash.Hash, salt []byte, data []byte, count int) [][]byte {

	result := make([][]byte, 2)
	key := make([]byte, keyLen)
	keyIx := 0
	iv := make([]byte, ivLen)
	ivIx := 0
	result[0] = key
	result[1] = iv
	var mdBuf []byte
	nkey := keyLen
	niv := ivLen
	i := 0
	if data == nil {
		return result
	}

	addmd := 0
	for {
		md.Reset()
		if addmd > 0 {
			md.Write(mdBuf)
		}
		addmd++
		md.Write(data)
		if salt != nil {
			md.Write(salt[:8])
		}
		mdBuf = md.Sum(nil)
		for i = 1; i < count; i++ {
			md.Reset()
			md.Write(mdBuf)
			mdBuf = md.Sum(nil)
		}
		i = 0
		if nkey > 0 {
			for {
				if nkey == 0 {
					break
				}
				if i == len(mdBuf) {
					break
				}
				key[keyIx] = mdBuf[i]
				keyIx++
				nkey--
				i++
			}
		}
		if niv > 0 && i != len(mdBuf) {
			for {
				if niv == 0 {
					break
				}
				if i == len(mdBuf) {
					break
				}
				iv[ivIx] = mdBuf[i]
				ivIx++
				niv--
				i++
			}
		}
		if nkey == 0 && niv == 0 {
			break
		}
	}
	for i = 0; i < len(mdBuf); i++ {
		mdBuf[i] = 0
	}

	return result
}
