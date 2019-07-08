# cipher

The cipher module provides functions for encrypting and decrypting data using aes-256-cbc mode in Go.

## Installation

To install the module, simply run:

`$ go get github.com/walkert/cipher`


## Getting Started

The example below shows a simple encryption/decryption of data using the RandomString helper function to generate the salt and password.

```go
package main

import (
    "fmt"
    "log"

    "github.com/walkert/cipher"
)

func main() {
    input := "cleartext"
    randomString := cipher.RandomString(20)
    salt := randomString[:10]
    pass := randomString[10:]
    encrypted, err := cipher.EncryptString(input, salt, pass)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Input val '%s' has been encrypted to '%s'\n", input, string(encrypted))
    decrypted, err := cipher.DecryptBytes(encrypted, salt, pass)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Converted encrypted string '%s' back to '%s'\n", string(encrypted), string(decrypted))
}
```
