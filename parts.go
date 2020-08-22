package ssm

import "github.com/neoxelox/ssm/cipher"

type public struct {
	Version    string                 `json:"version"`
	Encryption cipher.Type            `json:"encryption"`
	Metadata   map[string]interface{} `json:"metadata"`
}

type protected struct {
	Checksum  [32]byte               `json:"checksum"`
	Separator []byte                 `json:"separator"`
	Metadata  map[string]interface{} `json:"metadata"`
}
