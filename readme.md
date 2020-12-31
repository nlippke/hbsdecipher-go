# Hybrid Backup Sync decipher (go)

This is a port of the Java version of [Hybrid Backup Sync](https://github.com/Mikiya83/hbs_decipher) entirely
written in go, small in size (< 3MB) and fast.
It currently supports only QNAP HBS version 2 and OpenSSL ciphered files.

## Usage

    hbsdec (options) file1 directory2 ...
    Options:
      -o string
            output directory (optional)
      -p string
            password for decryption
      -r    traverse directories recursively
      -v    verbose

## Docker version

    docker build -t hbsdec .
    docker run --rm -it -v hostdirA:/in -v hostdirB:/out hbsdec -r -o /out /in  

## License:
Tool under GNU version 3 license.
