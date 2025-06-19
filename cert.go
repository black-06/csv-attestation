package csv_attestation

import (
	"crypto/elliptic"
	"math/big"
	"slices"
	"unsafe"

	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"
)

func VerifyCert(parent, cert Cert) error {
	pubkey, err := parent.GetEccPubkey()
	if err != nil {
		return errors.Wrap(err, "get root cert pubkey failed")
	}
	signature := cert.GetEccSignature()
	ok := sm2.Sm2Verify(&pubkey.PublicKey, cert.GetMessage(), pubkey.UID, signature.R, signature.S)
	if !ok {
		return errors.New("verify failed")
	}
	return nil
}

type EccPubkey struct {
	sm2.PublicKey
	UID []byte
}

type EccSignature struct{ R, S *big.Int }

type Cert interface {
	// GetEccPubkey returns a pubkey that verify other cert
	GetEccPubkey() (*EccPubkey, error)
	// GetEccSignature returns the signature to be verified
	GetEccSignature() *EccSignature
	// GetMessage returns the message to be verified
	GetMessage() []byte
}

// enum _key_usage
const (
	KEY_USAGE_TYPE_HRK     = 0
	KEY_USAGE_TYPE_HSK     = 0x13
	KEY_USAGE_TYPE_INVALID = 0x1000
	KEY_USAGE_TYPE_OCA     = 0x1001
	KEY_USAGE_TYPE_PEK     = 0x1002
	KEY_USAGE_TYPE_PDH     = 0x1003
	KEY_USAGE_TYPE_CEK     = 0x1004
)

const (
	HskCekCertSize           = int(unsafe.Sizeof(HskCekCert{}))
	ChipRootCertSize         = int(unsafe.Sizeof(ChipRootCert{}))
	CsvCertSize              = int(unsafe.Sizeof(CsvCert{}))
	CsvAttestationReportSize = int(unsafe.Sizeof(CsvAttestationReport{}))

	GUEST_ATTESTATION_DATA_SIZE  = 64
	GUEST_ATTESTATION_NONCE_SIZE = 16

	CHIP_KEY_ID_LEN     = 16
	SIZE_INT32          = 4
	SIZE_24             = 24
	SIZE_108            = 108
	SIZE_112            = 112
	CSV_CERT_RSVD3_SIZE = 624
	CSV_CERT_RSVD4_SIZE = 368
	CSV_CERT_RSVD5_SIZE = 368

	VM_ID_SIZE      = 16
	VM_VERSION_SIZE = 16
	SN_LEN          = 64
	USER_DATA_SIZE  = 64
	HASH_BLOCK_LEN  = 32
)

type HskCekCert struct {
	Hsk ChipRootCert
	Cek CsvCert
}

var _ Cert = (*ChipRootCert)(nil)

// ChipRootCert is _hygon_root_cert CHIP_ROOT_CERT_t
type ChipRootCert struct {
	Version      uint32
	KeyID        [CHIP_KEY_ID_LEN]byte
	CertifyingID [CHIP_KEY_ID_LEN]byte
	KeyUsage     uint32
	Reserved1    [SIZE_24 / SIZE_INT32]uint32
	Pubkey       [PUBKEY_SIZE]byte // it's union of pubkey, ecc_pubkey
	Reserved2    [SIZE_108 / SIZE_INT32]uint32
	Signature    [SIGNATURE_SIZE]byte // it's union of signature, ecc_sig
	Reserved3    [SIZE_112 / SIZE_INT32]uint32
}

func (cert *ChipRootCert) GetEccPubkey() (*EccPubkey, error) { return getEccPubkey(cert.Pubkey) }
func (cert *ChipRootCert) GetEccSignature() *EccSignature    { return getEccSignature(cert.Signature) }
func (cert *ChipRootCert) GetMessage() []byte {
	return (*[ChipRootCertSize]byte)(unsafe.Pointer(cert))[:64+512]
}

var _ Cert = (*CsvCert)(nil)

// CsvCert is _hygon_csv_cert  CSV_CERT_t
type CsvCert struct {
	Version  uint32
	ApiMajor uint8
	ApiMinor uint8

	Reserved1   uint8
	Reserved2   uint8
	PubkeyUsage uint32
	PubkeyAlgo  uint32
	Pubkey      [PUBKEY_SIZE]byte // it's union of pubkey, ecc_pubkey
	Reserved3   [CSV_CERT_RSVD3_SIZE / SIZE_INT32]uint32

	Sig1Usage uint32
	Sig1Algo  uint32
	Sig1      [SIGNATURE_SIZE]byte // it's union of sig1, ecc_sig1
	Reserved4 [CSV_CERT_RSVD4_SIZE / SIZE_INT32]uint32

	Sig2Usage uint32
	Sig2Algo  uint32
	Sig2      [SIGNATURE_SIZE]byte // it's union of sig2, ecc_sig2
	Reserved5 [CSV_CERT_RSVD5_SIZE / SIZE_INT32]uint32
}

func (cert *CsvCert) GetEccPubkey() (*EccPubkey, error) { return getEccPubkey(cert.Pubkey) }
func (cert *CsvCert) GetEccSignature1() *EccSignature   { return getEccSignature(cert.Sig1) }
func (cert *CsvCert) GetEccSignature2() *EccSignature   { return getEccSignature(cert.Sig2) }
func (cert *CsvCert) GetEccSignature() *EccSignature {
	if cert.Sig1Usage == KEY_USAGE_TYPE_INVALID {
		return cert.GetEccSignature2()
	} else {
		return cert.GetEccSignature1()
	}
}
func (cert *CsvCert) GetMessage() []byte {
	return (*[CsvCertSize]byte)(unsafe.Pointer(cert))[:16+1028]
}

var _ Cert = (*CsvAttestationReport)(nil)

// CsvAttestationReport is csv_attestation_report
type CsvAttestationReport struct {
	UserPubkeyDigest [HASH_BLOCK_LEN]byte
	VmID             [VM_ID_SIZE]byte
	VmVersion        [VM_VERSION_SIZE]byte
	UserData         [USER_DATA_SIZE / 4]uint32
	MNonce           [GUEST_ATTESTATION_NONCE_SIZE / 4]uint32
	Measure          [HASH_BLOCK_LEN / 4]uint32
	Policy           uint32
	SigUsage         uint32
	SigAlgo          uint32
	ANonce           uint32
	Sig1             [SIGNATURE_SIZE]byte // it's union of sig1, ecc_sig1
	PekCert          [CsvCertSize / 4]uint32
	SN               [SN_LEN / 4]uint32
	Reserved2        [32]byte
	Mac              [HASH_BLOCK_LEN]byte
}

func (report *CsvAttestationReport) GetEccPubkey() (*EccPubkey, error) {
	return nil, errors.New("report cannot verify other cert")
}
func (report *CsvAttestationReport) GetEccSignature() *EccSignature {
	return getEccSignature(report.Sig1)
}
func (report *CsvAttestationReport) GetMessage() []byte {
	return (*[CsvAttestationReportSize]byte)(unsafe.Pointer(report))[:180]
}

type ParsedReport struct {
	UserData []byte
	MNonce   []byte
	Measure  []byte
	PekCert  *CsvCert
	ChipID   string
}

func (report *CsvAttestationReport) ParseReport() *ParsedReport {
	userData := report.xorANonce(report.UserData[:])
	nonce := report.xorANonce(report.MNonce[:])
	measure := report.xorANonce(report.Measure[:])
	pekCert := report.xorANonce(report.PekCert[:])
	pekCertBytes := *(*[CsvCertSize]byte)(unsafe.Pointer(&pekCert[0]))

	sn := report.xorANonce(report.SN[:])
	snBytes := (*(*[SN_LEN]byte)(unsafe.Pointer(&sn[0])))[:]
	for len(snBytes) > 0 && snBytes[len(snBytes)-1] == 0 {
		snBytes = snBytes[:len(snBytes)-1]
	}
	return &ParsedReport{
		UserData: (*(*[USER_DATA_SIZE]byte)(unsafe.Pointer(&userData[0])))[:],
		MNonce:   (*(*[GUEST_ATTESTATION_NONCE_SIZE]byte)(unsafe.Pointer(&nonce[0])))[:],
		Measure:  (*(*[HASH_BLOCK_LEN]byte)(unsafe.Pointer(&measure[0])))[:],
		PekCert:  (*CsvCert)(unsafe.Pointer(&pekCertBytes[0])),
		ChipID:   string(snBytes),
	}
}

func (report *CsvAttestationReport) xorANonce(data []uint32) []uint32 {
	rst := make([]uint32, len(data))
	for i := range rst {
		rst[i] = data[i] ^ report.ANonce
	}
	return rst
}

const (
	PUBKEY_SIZE        = int(unsafe.Sizeof(eccPubkey{}))
	SIGNATURE_SIZE     = int(unsafe.Sizeof(eccSignature{}))
	ECC_POINT_SIZE     = 72
	HYGON_USER_ID_SIZE = 256
	ECC_LEN            = 32
)

// eccPubkey is ecc_pubkey_t
type eccPubkey struct {
	curveID uint32
	qx      [ECC_POINT_SIZE]byte
	qy      [ECC_POINT_SIZE]byte
	userID  userid
}

// userid is userid_t
type userid struct {
	len int16
	uid [HYGON_USER_ID_SIZE - 2]byte
}

// eccSignature is ecc_signature_t
type eccSignature struct {
	sigR, sigS [ECC_POINT_SIZE]byte
}

func getEccPubkey(data [PUBKEY_SIZE]byte) (*EccPubkey, error) {
	pubkey := (*eccPubkey)(unsafe.Pointer(&data))

	var curve elliptic.Curve
	// enum _curve_id
	switch pubkey.curveID {
	case 1:
		curve = elliptic.P256()
	case 2:
		curve = elliptic.P384()
	case 3:
		curve = sm2.P256Sm2()
	default:
		return nil, errors.Errorf("invalid curve id: %d", pubkey.curveID)
	}

	x := make([]byte, ECC_LEN)
	copy(x, pubkey.qx[:ECC_LEN])
	slices.Reverse(x)

	y := make([]byte, ECC_LEN)
	copy(y, pubkey.qy[:ECC_LEN])
	slices.Reverse(y)

	return &EccPubkey{
		PublicKey: sm2.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		},
		UID: pubkey.userID.uid[:pubkey.userID.len],
	}, nil
}

func getEccSignature(data [SIGNATURE_SIZE]byte) *EccSignature {
	signature := (*eccSignature)(unsafe.Pointer(&data))

	sigR := make([]byte, ECC_LEN)
	copy(sigR, signature.sigR[:ECC_LEN])
	slices.Reverse(sigR)

	sigS := make([]byte, ECC_LEN)
	copy(sigS, signature.sigS[:ECC_LEN])
	slices.Reverse(sigS)

	return &EccSignature{
		R: new(big.Int).SetBytes(sigR),
		S: new(big.Int).SetBytes(sigS),
	}
}
