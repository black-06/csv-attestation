//go:build !linux

package csv_attestation

import (
	"github.com/pkg/errors"
)

func IoctlGetAttestationReport(data []byte) (report, nonce []byte, err error) {
	return nil, nil, errors.New("only supported on linux")
}
