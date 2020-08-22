# ssm
**🔐 `Secure Secret Management` 🔐**

## What
A Secret is an encrypted piece of information, whereas a Fact is a "told" Secret, which you can manipulate. You can hide all sorts of data into a Secret, even more Secrets.

## Install
**`go get github.com/neoxelox/ssm`**

## Usage
**`Create Fact and convert to Secret`**
```go
fact, err := ssm.Create(cipher.Ciphers.Aes, nil)
if err == ssm.ErrEncryptionNotSupported {
    // Do something
    return
}

fact.Public.Metadata = map[string]interface{}{
    // Insert something
}

fact.Protected.Metadata = map[string]interface{}{
    // Insert something
}

fact.Private = [][]byte{[]byte("https://github.com/neoxelox/ssm")}

secret, err := fact.Hide("AwesomeKey")
switch err {
case ssm.ErrEncryptionNotSupported:
    // Do something
    return
case ssm.ErrEncryptionFailed:
    // Do something
    return
}
```

**`Parse Secret and convert to Fact`**
```go
jsonData := []byte(`
    {
        "public": {
        "version": "0.1.1",
        "encryption": "AES",
        "metadata": {
            "color": "6463fb",
            "keys": 1,
            "name": "GitHub"
        }
        },
        "private": "sPM54nv2F42RwZniPW4EmNz2P0i4l5Lxa/j0szQXFN6umTRDb+IxFjBzjLaAYeq/Zr2HSC6uugPQJ1k=",
        "protected": "JJCY4C8hR+o2MTjNR/7WwIBHkA54A8VAEDhn7pN7qT7Vov4Ud3k1tcP3C5mMLykwMOncJoVs7ZlkFVkAsHRgla6featTZvyOgW7BcEZfJX3VTypH6O6zLVbRxr5K+mijpWzq2t78KAISaej6PFefUxoS3BusleFGjjQP+DVN8Gb9t8WUY+Oh032LXrzsGnbKeB249LZ4B+qhG6TdjKs6ZMoPdTEZxfjFM9T+8fEcsdm+ShQApZgdokdIDfxwV3j7CwIewwc="
    }	  
`)

secret, err := ssm.Parse(jsonData)
if err == ssm.ErrNotASecret {
    // Do something
    return
}

fact, err := secret.Tell("AwesomeKey")
switch err {
case ssm.ErrEncryptionNotSupported:
    // Do something
    return
case ssm.ErrDecryptionFailed:
    // Do something
    return
case ssm.ErrChecksumMismatch:
    // Do something
    return
}
```

**`Persist to file`**
```go
secretJSON, err := json.Marshal(secret)
if err != nil {
    // Do something
    return
}

err = ioutil.WriteFile("secret.json", secretJSON, 0644)
if err != nil {
    // Do something
    return
}
```

See [`GoDev`](https://pkg.go.dev/github.com/neoxelox/ssm) for further documentation.

## Models
```yaml
Fact:
    public:
        version:    string
        encryption: cipher.Type
        metadata:   map[string]interface{}
    private: [][]byte
    protected:
        checksum:  [32]byte
        separator: []byte
        metadata:  map[string]interface{}
```

```yaml
Secret:
    public:
        version:    string
        encryption: cipher.Type
        metadata:   map[string]interface{}
    private:   []byte
    protected: []byte
```

## Contribute
Feel free to contribute to this project : ) .

## License
This project is licensed under the [MIT License](https://opensource.org/licenses/MIT) - read the [LICENSE](LICENSE) file for details.
