package main

import (
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh/terminal" //nolint:gci
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const application string = "hbsdec"
const ver string = "0.1.0"
const errparameters int = 1
const errordecipher int = 2

var password *string
var verbose *bool
var outDirectory *string
var inDirectory string
var failures int

func main() {
	flag.Usage = func() {
		fmt.Printf("%s v%s (options) file1 directory2 ...\nOptions:\n", application, ver)
		flag.PrintDefaults()
	}

	password = flag.String("p", "", "password for decryption")
	recursive := flag.Bool("r", false, "traverse directories recursively")
	verbose = flag.Bool("v", false, "verbose")
	outDirectory = flag.String("o", "", "output directory (optional)")
	flag.Parse()
	filesOrDirectories := flag.Args()

	if len(filesOrDirectories) == 0 {
		_, _ = fmt.Fprintln(os.Stderr, "need at least one file or directory")

		flag.Usage()

		os.Exit(errparameters)
	}

	if len(*password) == 0 {
		p, err := readPassword()
		if err != nil || len(p) == 0 {
			_, _ = fmt.Fprintf(os.Stderr, "\n\nMissing password!!!")

			os.Exit(errparameters)
		}

		password = &p
	}

	if len(*outDirectory) > 0 {
		if *verbose {
			fmt.Printf("Start deciphering into %s\n", *outDirectory)
		}

		if err := os.MkdirAll(*outDirectory, os.ModePerm); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%v", err)
			os.Exit(errparameters)
		}
	}

	failures = 0

	for _, fileOrDirectory := range filesOrDirectories {

		f, err := os.Stat(fileOrDirectory)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%v\n", err)
			failures++
		}
		if f.IsDir() {
			inDirectory = fileOrDirectory
		} else {
			inDirectory = filepath.Dir(fileOrDirectory)
		}

		if *recursive {
			if err := filepath.Walk(fileOrDirectory, processFileOrDirectory); err != nil {
				failures++
			}
		} else {
			entries, err := ReadDir(fileOrDirectory)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "%v", err)
			}
			for _, entry := range entries {
				_ = processFileOrDirectory(filepath.Clean(filepath.Dir(fileOrDirectory)+"/"+entry.Name()),
					entry, nil)
			}
		}
	}

	if failures > 0 {
		os.Exit(errordecipher)
	}

	os.Exit(0)
}

func readPassword() (string, error) {
	fmt.Print("Enter Password: ")

	bytePassword, err := terminal.ReadPassword(syscall.Stdin)
	if err != nil {
		return "", err
	}

	password := string(bytePassword)

	return strings.TrimSpace(password), nil
}

func processFileOrDirectory(path string, info os.FileInfo, err error) error {
	if err != nil {
		return err
	}

	if info.IsDir() {
		return nil
	}

	var plainFileName string

	if len(*outDirectory) != 0 {
		if strings.HasPrefix(path, inDirectory) {
			plainFileName = filepath.Clean(*outDirectory + "/" + path[len(inDirectory):])
		} else {
			plainFileName = filepath.Clean(*outDirectory + "/" + info.Name())
		}
	} else {
		plainFileName = filepath.Clean(filepath.Dir(path) + "/" + "plain_" + info.Name())
	}

	if strings.HasSuffix(plainFileName, QnapBz2Extension) {
		plainFileName = plainFileName[0:strings.LastIndex(plainFileName, QnapBz2Extension)]
	}

	err = DecipherFile(&DecipherParam{
		CipheredFileName: path,
		PlainFileName:    plainFileName,
		Password:         *password,
		Verbose:          *verbose,
	})

	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)

		if errors.Is(err, ErrDecipher) {
			failures++
		}
	}

	return nil
}

// ReadDir reads the directory named by dirname and returns
// a list of directory entries sorted by filename.
// If argument is a file instead of a directory it's info is returned.
func ReadDir(dirname string) ([]os.FileInfo, error) {
	f, err := os.Open(dirname)
	if err != nil {
		return nil, err
	}

	ftype, err := f.Stat()
	if err != nil {
		return nil, err
	}

	if !ftype.IsDir() {
		return []os.FileInfo{ftype}, nil
	}

	list, err := f.Readdir(-1)

	_ = f.Close()

	if err != nil {
		return nil, err
	}

	sort.Slice(list, func(i, j int) bool { return list[i].Name() < list[j].Name() })

	return list, nil
}
