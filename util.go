package ssm

import (
	"fmt"
)

const base = 1024

func byteSize(length int) string {
	var sbytes string

	if length < base {
		sbytes = fmt.Sprintf("%dB", length)
	} else {
		div, exp := int64(base), 0
		for n := length / base; n >= base; n /= base {
			div *= base
			exp++
		}
		sbytes = fmt.Sprintf("%.1f%cB", float64(length)/float64(div), "KMGTPE"[exp])
	}

	return sbytes
}
