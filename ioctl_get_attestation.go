//go:build linux

package csv_attestation

import (
	"crypto/rand"
	"io"
	"unsafe"

	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm3"
	"golang.org/x/sys/unix"
)

// CsvGuestMem is csv_guest_mem
type CsvGuestMem struct {
	Va   uintptr
	Size int32
}

func IoctlGetAttestationReport(data []byte) (report, nonce []byte, err error) {
	const (
		PAGE_SIZE                         = 1 << 12
		GUEST_ATTESTATION_DATA_NONCE_SIZE = GUEST_ATTESTATION_DATA_SIZE + GUEST_ATTESTATION_NONCE_SIZE

		IOC_WRITE = 1
		IOC_READ  = 2

		IOC_TYPEBITS = 8
		IOC_NRBITS   = 8
		IOC_SIZEBITS = 14

		IOC_NRSHIFT   = 0
		IOC_TYPESHIFT = IOC_NRSHIFT + IOC_NRBITS
		IOC_SIZESHIFT = IOC_TYPESHIFT + IOC_TYPEBITS
		IOC_DIRSHIFT  = IOC_SIZESHIFT + IOC_SIZEBITS

		CSV_GUEST_IOC_TYPE = 'D'
		// GET_ATTESTATION_REPORT
		// 	ioc(dir, typ, nr, size) = (dir << IOC_DIRSHIFT) | (typ << IOC_TYPESHIFT) | (nr << IOC_NRSHIFT) | (size << IOC_SIZESHIFT)
		// 	iowr(typ, nr, size)     = ioc(IOC_READ | IOC_WRITE, typ, nr, size)
		// 	GET_ATTESTATION_REPORT  = iowr(CSV_GUEST_IOC_TYPE, 1, 16) // sizeof(struct csv_guest_mem)
		GET_ATTESTATION_REPORT = ((IOC_READ | IOC_WRITE) << IOC_DIRSHIFT) | (CSV_GUEST_IOC_TYPE << IOC_TYPESHIFT) | (1 << IOC_NRSHIFT) | (int(unsafe.Sizeof(CsvGuestMem{})) << IOC_SIZESHIFT)
	)

	nonce = make([]byte, GUEST_ATTESTATION_NONCE_SIZE)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, nil, errors.Wrap(err, "generate nonce failed")
	}

	//	struct csv_attestation_user_data {
	//	   uint8_t data[GUEST_ATTESTATION_DATA_SIZE]; //
	//	   uint8_t mnonce[GUEST_ATTESTATION_NONCE_SIZE];
	//	   hash_block_u hash;
	//	};
	//
	//	typedef struct _hash_block_u {
	//	    unsigned char block[HASH_LEN];
	//	} hash_block_u;
	var userData [PAGE_SIZE]byte
	copy(userData[:GUEST_ATTESTATION_DATA_SIZE], data)
	copy(userData[GUEST_ATTESTATION_DATA_SIZE:GUEST_ATTESTATION_DATA_NONCE_SIZE], nonce)
	copy(userData[GUEST_ATTESTATION_DATA_NONCE_SIZE:], sm3.Sm3Sum(userData[:GUEST_ATTESTATION_DATA_NONCE_SIZE]))

	mem := CsvGuestMem{Va: uintptr(unsafe.Pointer(&userData)), Size: PAGE_SIZE}
	fd, err := unix.Open("/dev/csv-guest", unix.O_RDWR, 0)
	if err != nil {
		return nil, nil, errors.Wrap(err, "open /dev/csv-guest failed")
	}
	defer func() { _ = unix.Close(fd) }()

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(GET_ATTESTATION_REPORT), uintptr(unsafe.Pointer(&mem)))
	if errno != 0 {
		return nil, nil, errors.Wrapf(err, "ioctl GET_ATTESTATION_REPORT failed, errno: %v", errno)
	}
	return userData[:CsvAttestationReportSize], nonce, nil
}
