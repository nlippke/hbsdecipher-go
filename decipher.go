package main

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" //nolint:gosec
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	AesKeyStrength   int    = 256
	QnapBz2Extension string = ".qnap.bz2"
	BlockSize        int    = 16
	HeaderV2Length   int64  = 80
	IndexIv          int    = 1
	IndexKey         int    = 0
	ITERATIONS       int    = 1
	SaltSize         int    = 8
)

var NoCipherFile error = errors.New("not a ciphered file")
var ErrDecipher error = errors.New("failed to decipher file")

var QNAPFilePrefixV1Bytes = []byte{7, 95, 95, 81, 67, 83, 95, 95}
var QNAPFilePrefixV2Bytes = []byte{75, 202, 148, 114, 94, 131, 28, 49}
var OpenSSLPrefix = []byte{'S', 'a', 'l', 't', 'e', 'd', '_', '_'}

// Encrypted header information.
type encryptHeader struct {
	size uint64
	ckey []byte
	salt []byte
}

type fileType struct {
	compressed     bool
	encryptVersion int
}

type Decipher struct {
	header     *encryptHeader
	ftype      *fileType
	cipherFile *os.File
	plainFile  *os.File
	password   string
	verbose    bool
}

type DecipherParam struct {
	CipheredFileName string
	PlainFileName    string
	Password         string
	Verbose          bool
}

func (d *Decipher) logVerbosef(format string, v ...interface{}) {
	if d.verbose {
		_, _ = fmt.Fprintf(os.Stderr, format, v...)
	}
}

// decipherFile deciphers a QNAP cipherFile into a plainFile.
func DecipherFile(param *DecipherParam) error {
	d := &Decipher{
		verbose:  param.Verbose,
		password: param.Password,
	}

	var err error

	if d.cipherFile, err = os.Open(param.CipheredFileName); err != nil {
		return fmt.Errorf("invalid input file: %w", err)
	}

	defer func() {
		_ = d.cipherFile.Close()
	}()

	d.ftype = d.checkCipheredFile()

	if d.ftype.encryptVersion >= 0 {
		if d.plainFile, err = os.Create(param.PlainFileName); err != nil {
			return fmt.Errorf("%w: invalid target file: %v", ErrDecipher, err)
		}

		defer func() {
			_ = d.plainFile.Close()
		}()
	}

	switch {
	case d.ftype.encryptVersion == 0:
		d.logVerbosef("decipher %s (type: OpenSSL)\n", d.cipherFile.Name())

		_, err = d.doDecipherOpenSSL()

		return err
	case d.ftype.encryptVersion == 1:
		d.logVerbosef("decipher %s (type:%d, compressed:%t)\n",
			d.cipherFile.Name(), d.ftype.encryptVersion, d.ftype.compressed)

		return fmt.Errorf("%w: HBS cipher type 1 is currently not supported", NoCipherFile)
	case d.ftype.encryptVersion == 2:
		d.logVerbosef("decipher %s (type:%d, compressed:%t)\n",
			d.cipherFile.Name(), d.ftype.encryptVersion, d.ftype.compressed)

		_, err = d.doDecipherV2()

		return err
	default:
		d.logVerbosef("%s is not recognized as ciphered file\n", d.cipherFile.Name())

		return NoCipherFile
	}
}

func (d *Decipher) doDecipherV2() (uint64, error) {
	var err error
	if d.header, err = d.decipherV2Header(d.cipherFile, password); err != nil {
		return 0, err
	}

	var writer *bufio.Writer

	var tmpFile *os.File

	if d.ftype.compressed {
		tmpFileName := d.plainFile.Name() + ".tmp"

		tmpFile, err = os.Create(d.plainFile.Name() + ".tmp")
		if err != nil {
			return 0, fmt.Errorf("%w: cannot create tmp file %s (%v)", ErrDecipher, tmpFileName, err)
		}

		writer = bufio.NewWriter(tmpFile)
	} else {
		writer = bufio.NewWriter(d.plainFile)
	}

	bytesWritten, err := d.doDecipher(bufio.NewReader(d.cipherFile), writer)

	if d.ftype.compressed {
		d.logVerbosef("deciphering ok. decompressing file...")

		if _, err = tmpFile.Seek(0, 0); err != nil {
			return 0, fmt.Errorf("%w", err)
		}

		out, err := io.Copy(bufio.NewWriter(d.plainFile), flate.NewReader(tmpFile))
		bytesWritten = uint64(out)
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())

		if err != nil {
			return bytesWritten, fmt.Errorf("%w: failed to decompress file (%v)", ErrDecipher, err)
		}
	}

	if err != nil {
		return 0, err
	}

	if bytesWritten != d.header.size {
		return bytesWritten, ErrDecipher
	}

	return bytesWritten, nil
}

func (d *Decipher) doDecipherOpenSSL() (uint64, error) {
	if _, err := d.cipherFile.Seek(8, 0); err != nil {
		return 0, fmt.Errorf("%w", err)
	}

	salt := make([]byte, SaltSize)

	n, err := io.ReadFull(d.cipherFile, salt)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrDecipher, err)
	}

	if n < len(salt) {
		return 0, fmt.Errorf("%w: premature end of file", ErrDecipher)
	}

	digest := md5.New()

	// create key and IV
	// the IV is useless, OpenSSL might as well have used zero's
	keyAndIV := EVPBytesToKey(AesKeyStrength/8, 16, digest, salt, []byte(d.password), ITERATIONS)
	d.header = &encryptHeader{
		ckey: keyAndIV[IndexKey],
		salt: keyAndIV[IndexIv],
	}
	tmpFileName := d.plainFile.Name() + ".tmp"

	tmpFile, err := os.Create(d.plainFile.Name() + ".tmp")
	if err != nil {
		return 0, fmt.Errorf("%w: cannot create tmp file %s (%v)", ErrDecipher, tmpFileName, err)
	}

	defer func() {
		_ = tmpFile.Close()
		err = os.Remove(tmpFileName)
	}()

	_, err = d.doDecipher(bufio.NewReader(d.cipherFile), bufio.NewWriter(tmpFile))
	if err != nil {
		return 0, err
	}

	d.logVerbosef("deciphering ok. decompressing file...")

	if _, err = tmpFile.Seek(0, 0); err != nil {
		return 0, fmt.Errorf("%w", err)
	}

	bytesWritten, err := io.Copy(bufio.NewWriter(d.plainFile), bzip2.NewReader(tmpFile))
	if err != nil {
		return uint64(bytesWritten), fmt.Errorf("%w: failed to decompress file (%v)", ErrDecipher, err)
	}

	return uint64(bytesWritten), nil
}

// doDecipher does the actual deciphering using AES/CBC/PKCS5Padding.
func (d *Decipher) doDecipher(reader *bufio.Reader, writer *bufio.Writer) (uint64, error) {
	var bytesWritten uint64

	if d.ftype.encryptVersion == 2 {
		if _, err := d.cipherFile.Seek(HeaderV2Length, 0); err != nil {
			return bytesWritten, err
		}
	}

	block, err := aes.NewCipher(d.header.ckey)
	if err != nil {
		return bytesWritten, err
	}

	blockSize := BlockSize * BlockSize
	ecb := cipher.NewCBCDecrypter(block, d.header.salt)
	encrypted := make([]byte, blockSize)
	decrypted := make([]byte, blockSize)

	for {
		n, err := reader.Read(encrypted)
		if err != nil {
			return bytesWritten, fmt.Errorf("%w: %v", ErrDecipher, err)
		}

		if n < blockSize {

			if n%16 != 0 {
				return bytesWritten, fmt.Errorf("%w: invalid blocksize", ErrDecipher)
			}

			ecb.CryptBlocks(decrypted, encrypted[0:n])

			if decrypted, err = d.PKCS5Trimming(decrypted[:n], block.BlockSize()); err != nil {
				return bytesWritten, fmt.Errorf("%w: %v", ErrDecipher, err)
			}
			if n, err := writer.Write(decrypted); err != nil {
				return bytesWritten, fmt.Errorf("%w: %v", ErrDecipher, err)
			} else {
				bytesWritten += uint64(n)
			}

			break
		}

		ecb.CryptBlocks(decrypted, encrypted)

		if n, err := writer.Write(decrypted); err != nil {
			return bytesWritten, fmt.Errorf("%w: %v", ErrDecipher, err)
		} else {
			bytesWritten += uint64(n)
		}
	}

	_ = writer.Flush()

	return bytesWritten, nil
}

// PKCS5Trimming unpadds a block.
func (d *Decipher) PKCS5Trimming(src []byte, blockSize int) ([]byte, error) {
	srcLen := len(src)
	paddingLen := int(src[srcLen-1])

	if paddingLen >= srcLen || paddingLen > blockSize {
		return nil, fmt.Errorf("%w: invalid padding, maybe incorrect password", ErrDecipher)
	}

	return src[:srcLen-paddingLen], nil
}

// checkCipheredFile tests if the file is any QNAP-ciphered file.
func (d *Decipher) checkCipheredFile() *fileType {
	magic := make([]byte, 8)
	// skip rest of header
	n, err := io.ReadFull(d.cipherFile, magic)
	if err != nil || n < len(magic) {
		return &fileType{
			encryptVersion: -1,
		}
	}

	if bytes.Equal(magic, OpenSSLPrefix) {
		return &fileType{
			encryptVersion: 0,
		}
	}

	if bytes.Equal(magic, QNAPFilePrefixV1Bytes) {
		return &fileType{
			encryptVersion: 1,
		}
	}

	if bytes.Equal(magic, QNAPFilePrefixV2Bytes) {
		compressOptions := make([]byte, 2)
		if n, err := io.ReadFull(d.cipherFile, compressOptions); n < len(compressOptions) || err != nil {
			return &fileType{
				encryptVersion: -1,
			}
		}
		return &fileType{
			compressed:     compressOptions[1] == 1,
			encryptVersion: 2,
		}
	}

	return &fileType{
		compressed:     false,
		encryptVersion: -1,
	}
}

// decipherHeader deciphers the first 64 bytes (header) of the file using AES/ECB/NoPadding.
func (d *Decipher) decipherV2Header(file *os.File, password *string) (*encryptHeader, error) {
	// skip file header
	if _, err := file.Seek(16, 0); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecipher, err)
	}

	iter := 1 + 32/len(*password)
	passwordFinal := []byte(strings.Repeat(*password, iter)[0:32])

	block, err := aes.NewCipher(passwordFinal)
	if err != nil {
		return nil, err
	}

	in := make([]byte, 64)
	out := make([]byte, 64)

	n, err := io.ReadFull(file, in)
	if n < 64 {
		return nil, fmt.Errorf("%w: failed to read file header (end of stream)", ErrDecipher)
	}

	if err != nil {
		return nil, err
	}

	for i := 0; i < 4; i++ {
		block.Decrypt(out[i*16:(i+1)*16], in[i*16:(i+1)*16])
	}

	// convert 8 byte size to uint64
	buf := make([]byte, 8)
	copy(buf, out[56:64])
	size := binary.BigEndian.Uint64(buf)
	// Struct is : magic [8] + ckey[32] + salt [16] + size [8]
	return &encryptHeader{
		ckey: out[8:40],
		salt: out[40:56],
		size: size,
	}, nil
}
