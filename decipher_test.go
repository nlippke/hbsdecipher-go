package main

import (
	"bufio"
	"bytes"
	"os"
	"strings"
	"testing"
)

const testpassword string = "test123"
const plainText string = "This is plain text."
const debug bool = false

func TestMain(m *testing.M) {
	if err := os.Mkdir("out", os.ModePerm); err != nil {
		panic(err)
	}

	result := m.Run()
	_ = os.RemoveAll("out")
	os.Exit(result)
}

func TestV2NotCompressed(t *testing.T) {
	err := DecipherFile(&DecipherParam{
		CipheredFileName: "examples/qnap_v2_not_compressed.txt",
		PlainFileName:    "out/qnap_v2_not_compressed.txt",
		Password:         testpassword,
		Verbose:          debug,
	})
	if err != nil {
		t.Errorf("%v", err)
	}
	result, _ := readFile("out/qnap_v2_not_compressed.txt")

	if strings.Compare(*result, plainText) != 0 {
		t.Errorf("Expected '%s' but got '%s'", plainText, *result)
	}
}

func TestV2Compressed(t *testing.T) {
	err := DecipherFile(&DecipherParam{
		CipheredFileName: "examples/qnap_v2_compressed.txt",
		PlainFileName:    "out/qnap_v2_compressed.txt",
		Password:         testpassword,
		Verbose:          debug,
	})
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	result, _ := readFile("out/qnap_v2_compressed.txt")

	if !strings.HasPrefix(*result, "0123456789") {
		t.Errorf("Expected '0123456789...' but got '%s'", (*result)[0:10])
	}
}

func TestOpenSSLNotCompressed(t *testing.T) {
	err := DecipherFile(&DecipherParam{
		CipheredFileName: "examples/openssl.txt",
		PlainFileName:    "out/openssl.txt",
		Password:         testpassword,
		Verbose:          debug,
	})
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	result, _ := readFile("out/openssl.txt")

	if strings.Compare(*result, plainText) != 0 {
		t.Errorf("Expected '%s' but got '%s'", plainText, *result)
	}
}

func TestOpenSSLCompressed(t *testing.T) {
	err := DecipherFile(&DecipherParam{
		CipheredFileName: "examples/openssl.txt.qnap.bz2",
		PlainFileName:    "out/openssl.txt",
		Password:         testpassword,
		Verbose:          debug,
	})
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	result, _ := readFile("out/openssl.txt")

	if !strings.HasPrefix(*result, "0123456789") {
		t.Errorf("Expected '0123456789...' but got '%s'", (*result)[0:10])
	}
}

func readFile(name string) (*string, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	r := bufio.NewReader(f)

	in := make([]byte, 1024)
	buf := bytes.NewBuffer(make([]byte, 0))

	for {
		n, _ := r.Read(in)
		if n > 0 {
			buf.Write(in[0:n])
		}
		if n < len(in) {
			break
		}
	}

	result := buf.String()

	return &result, nil
}
