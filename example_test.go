package ssm_test

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/neoxelox/ssm"
	"github.com/neoxelox/ssm/cipher"
)

// Example: create a simple Fact and hide it
func ExampleCreate_simple() {
	fact, err := ssm.Create(cipher.Ciphers.Aes, nil)
	if err == ssm.ErrEncryptionNotSupported {
		// Do something
		return
	}

	fact.Public.Metadata = map[string]interface{}{
		"keys":  1,
		"name":  "GitHub",
		"color": "6463fb",
	}

	fact.Protected.Metadata = map[string]interface{}{
		"created_at":     time.Now(),
		"last_view_at":   time.Now(),
		"last_change_at": time.Now(),
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

	secretJSON, err := json.MarshalIndent(secret, "", "  ")
	if err != nil {
		// Do something
		return
	}

	fmt.Println(string(secretJSON))

	// Output:
	// {
	//   "public": {
	// 	   "version": "0.1.2",
	// 	   "encryption": "AES",
	// 	   "metadata": {
	// 	     "color": "6463fb",
	// 	     "keys": 1,
	// 	     "name": "GitHub"
	//     }
	//   },
	//   "private": "udif2nhqJCcQamkaTnYh4PQxQolZDReB+MRQZZ74eANGsVJLWJ7edLdA8zUQfklQtS1nHCjRyc1Ami8=",
	//   "protected": "UO7zqefb92GXVFv9mpmDqhFooRz+7kjNftsD7zRzaGacDhZuXWUVxl48vh913h/u0HK/w0Bb7ErHq/9Bmj+vDSHAtp5Z0N73F0UDijFe+HqExTivKw1DyJnxoPrb3WYE5UZ8NyIVvD0gNUIuOavGBNzaeAGlhM8Ub8I1gJ/cKoAEpKIvzMP5dJKIR1KJ1OcUuTe45p65yruus7eoUifl5NLm9nVH4aXJvmVp+xVM9NIIrUR6/WuXPVamR5VA5EnZ+Gy4Nx5S+Ewyfp+AAh7LEXvwaZuuxPRPwgdAQ4V7cUYocoLMyD1CsGhKVAO+RoBnury1WDnkrOiJPdSFm1ovxG1Gc/m2cREmndC/5EKJh0xGMCCZdXm+LQb7FIIYr8+7eeBH7JeUCeKRqR9VEE3Qcxj9n13htzcItlzXKR8io1FQ7/1iwOIB1g1Qlqwa8G7vKHpzNMCEwtO4eheQ4EHkS40/zQ=="
	// }
}

// Example: create a Fact with several secrets and Hide it
func ExampleCreate_composed() {
	childFact, err := ssm.Create(cipher.Ciphers.Aes, nil)
	if err == ssm.ErrEncryptionNotSupported {
		// Do something
		return
	}

	childFact.Public.Metadata = map[string]interface{}{
		"keys":  1,
		"name":  "GitHub",
		"color": "6463fb",
	}

	childFact.Protected.Metadata = map[string]interface{}{
		"created_at":     time.Now(),
		"last_view_at":   time.Now(),
		"last_change_at": time.Now(),
	}

	childFact.Private = [][]byte{[]byte("https://github.com/neoxelox/ssm")}

	childSecret, err := childFact.Hide("AwesomeKey")
	switch err {
	case ssm.ErrEncryptionNotSupported:
		// Do something
		return
	case ssm.ErrEncryptionFailed:
		// Do something
		return
	}

	childSecretJSON, err := json.Marshal(childSecret)
	if err != nil {
		// Do something
		return
	}

	parentFact, err := ssm.Create(cipher.Ciphers.Aes, nil)
	if err == ssm.ErrEncryptionNotSupported {
		// Do something
		return
	}

	parentFact.Private = [][]byte{childSecretJSON, []byte("I'm the parent"), []byte("Awesome!"), childSecretJSON}

	parentSecret, err := parentFact.Hide("BreathtakingKey")
	switch err {
	case ssm.ErrEncryptionNotSupported:
		// Do something
		return
	case ssm.ErrEncryptionFailed:
		// Do something
		return
	}

	parentSecretJSON, err := json.MarshalIndent(parentSecret, "", "  ")
	if err != nil {
		// Do something
		return
	}

	fmt.Println(string(parentSecretJSON))

	// Output:
	// {
	//   "public": {
	// 	   "version": "0.1.2",
	// 	   "encryption": "AES",
	// 	   "metadata": null
	// 	 },
	// 	 "private": "4zMsjvYNT+NNMLeotmfXEDw8wff40JURPgYKumoajpCWA8Cnqilm6rbnxHK2oakaIbIdPZwbzthjBUbGYO/BToj8JDgMfL0ST+kDrcFUC3vjwWk6GEeSK7HwNJDotRSQBvmzQU1LI/MGDQLgpArLhIZk8dolX+mQ2FIOBUQC6JvyGS16k/FsseIlqcIQba9TDb54ZoB+F5EgDYBDFQtAImby8sXwAW03vbl82x2ntz9+eK4Fmz1Jh2V5Qg1UwHWUEkX937s8hz24M0JK+WbCNC2+Kh0MKXS08ZsspHjfTUEFpYpugGAN5I0KLLeKP+t8KHyHlOhMCMg8epqZmW/LTsuUcy1IUWGlAovdbSWJZ83BRFebe2aFJg0lW4OJzaULeSQHQZly44v344ZfjLwVWHLJ4Hi39XPGXkXqJftNpjhdWaamxGrqIO0rc/kYb0wzyYeg09b3c9+S60GgB4DVf5TrMeYLkszStEaLK5X8KdrFoJh3/q3dn3ycmSZUKu0eIsPCNSYNOEE6/Rwc7KDoM5TDvekztANGkby5WZ/ODRvcyKgBWlo+Q6qA21Q606iUu5A/oc1ib4C1r3H/BLZfEDiGp41Snj+vOpCDrbJCbpL4oyNTp1wDSrVzD3bbWfrPeUj4UMmv2usfHOinl51phXgzLme/P1TvZecOWqD34IvHvF/hb/4NU2sXFGP3jwEZsn5cRqVjqztQ8jfd+59bJHLztwpsOYsJ+Z+U/imKjkFfdxkR81u6wP6mQkzlZckX+teGUneb+bTbyPTg0fgxmWCmgiDJzsADHGgfgbCdUpP6ZBt4Coc7gNqmX11mqs6tvu7Ct0j0X23rnhGlD/dN6KVxA1Tt4J/faoZvFZ8wDBaO76OmeoDeoXGPuesG2MpfRXxhOgY1l5BGgt+8SD7guUZ4RBQPSN8Hqyih2v3wwYivm/qXbkDbPZAQk4glPr+NuQQiNoFmqzL/PFd3i5kWAf2PJQm7aHcdNSctmKM2cPW0vyCCOJFboWNRm+qICYJz45v9da1sxOQNNL0CBF9ZsSeB7eWrggoheL0hD4pEHiv5G6H6mHIhRgqX0ZTSD8kzFDc21AvL3RmyDQSWJ1UGwMQG+d6p/9uyulPL1qe8kZIEP+wPRLj+bbTzK9QLs68TnigJX9HthcTVp3HWMeyJb7SZsYc6WQJdyuLGDZ4sEnlGFu3jF+BOZAGJu125S15Qtcr7x4sbXIATL3BfgAIoUmaJkAbm2pGwyEpYzlwzJLByyOF9W0TCjcnmbjmRHmpMaoCKWdLTE3k2EFNP4muTXw88Wm7MNdZSorAuX/3+FhaGM4ue2pH3AGug3ZzmDLu/jrwi5rgTWMXacd7OUhiFPsJXhgBQkT5yA2dwZakDUP/GzzX/GwyUsgjC3BXUPvOOsPKAXbT/T75ClTWPOAdjH9UM3y3ak4bHR8n7GocarozgtbHBfZpmAA3nnA2jPj03O/OOl8R7TwGCkoIneWVAuaQk1jlz7yXMc8o3qtYimIUG0+b+VypChg5ZRhqHJeGiXVL2XVIpKRunXpTkc6/Q1zfHWpi2I7j813089SrmrwkgA2sOh9LZ3wnDuCt/Hcgck0YI/oz2m+jrHhVx09hcK3DQSvAsq8c0i8ZKJ2K/clyCe2m6E2R5vW0iAwz8Entyj4geQVc5IhIWzGRiPor16adivGUp7EGQUF1OYkvm02iqtVHbHV9coJKrxLiqDZrds67A+QH+2+kO1hJ4IbRgZMANEwkQbOrK2e/REGvWMwIfoU4CgvgCuTIJcopOjhkt/Lp30q0er1hZV1p++b+bgmq+AdMNPKqKrY+5dUm30Hx/lDgQcYr4TNyl/bK0lVr4k0cdMSneYBhBth2ygVHWZPnSUGHK1v3iTQOWmSvO5kTEb1fkuJ1+wMhoiyUJ3cuVyvqnAA==",
	// 	 "protected": "/VL1wlMYsU+ftYLyt6+koj3zsdr/BoilGuY5FWoX9RDaExJmaBQTa5WFsv6n7qSDiqrwF3taVPoEb46pAn7oDBZtZvuBy6pftG1Je54xs8kXlGMnJi6IGL9fXmIM7bGT/oG6ak/vv6KSKnZabBA58HUmFAnIB3VYJvf0dJ5gxHcqKOsYkCGA2yddJtcOW/DXCzRQagt/fNHkPrrcDx8i5yyWJwfVG7XLrwRnOBKGSkRB0ILFz6iKps40q3y3QtEJIaI="
	// }
}

// Example: parse a Secret from byte data and Tell it
func ExampleParse() {
	jsonData := []byte(`
	    {
		  "public": {
		    "version": "0.1.2",
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

	fmt.Println(string(fact.Private[0]))
	// Output: https://github.com/neoxelox/ssm
}
