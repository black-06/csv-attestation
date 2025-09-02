package csv_attestation

import (
	"bytes"
	"crypto/hmac"
	"fmt"
	"io"
	"net/http"
	"unsafe"

	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm3"
)

func Verify(reportData, nonceData []byte) error {
	if len(reportData) != CsvAttestationReportSize {
		return errors.New("invalid report content")
	}
	if len(nonceData) != GUEST_ATTESTATION_NONCE_SIZE {
		return errors.New("invalid nonce content")
	}
	report := (*CsvAttestationReport)(unsafe.Pointer(&reportData[0]))
	parsedReport := report.ParseReport()
	if err := VerifySessionMac(report, parsedReport.MNonce); err != nil {
		return errors.Wrap(err, "pek cert and chip id have been tampered")
	}
	if err := VerifyCertChain(parsedReport.ChipID, parsedReport.PekCert); err != nil {
		return errors.Wrap(err, "verify cert chain failed")
	}
	if err := VerifyCert(parsedReport.PekCert, report); err != nil {
		return errors.Wrap(err, "verify report failed")
	}
	if !bytes.Equal(nonceData, parsedReport.MNonce) {
		return errors.New("nonce incorrect")
	}
	return nil
}

var emptyReportReserved2 = string(make([]byte, 32))

func VerifySessionMac(report *CsvAttestationReport, nonce []byte) error {
	if string(report.Reserved2[:]) == emptyReportReserved2 {
		// report.reserved2 has been deleted, so we cannot verify mac
		// see https://gitee.com/anolis/hygon-devkit/blob/master/csv/attestation/csv_sdk/ioctl_get_attestation_report.c#L135
		return nil
	}
	const sumLen = 0x9D4 - 0x150 // sum bytes = PekCert + SN + Reserved2
	mac := hmac.New(sm3.New, nonce)
	mac.Write((*[sumLen]byte)(unsafe.Pointer(&report.PekCert))[:])
	if !bytes.Equal(mac.Sum(nil), report.Mac[:]) {
		return errors.New("verify report mac failed")
	}
	return nil
}

func VerifyCertChain(chipID string, pek *CsvCert) error {
	hrk, err := LoadHrkCert()
	if err != nil {
		return errors.Wrap(err, "load hrk failed")
	}
	// check hrk
	if hrk.KeyUsage != KEY_USAGE_TYPE_HRK {
		return errors.New("hrk.cert key_usage field incorrect")
	}

	hskCekCert, err := LoadHskCekCert(chipID)
	if err != nil {
		return errors.Wrap(err, "load hsk_cek failed")
	}
	hsk, cek := &hskCekCert.Hsk, &hskCekCert.Cek
	// check hsk cek
	if hsk.KeyUsage != KEY_USAGE_TYPE_HSK {
		return errors.New("hsk.cert key_usage field incorrect")
	}
	if cek.PubkeyUsage != KEY_USAGE_TYPE_CEK {
		return errors.New("cek.cert pub_key_usage field incorrect")
	}
	if cek.Sig1Usage != KEY_USAGE_TYPE_HSK {
		return errors.New("cek.cert sig_1_usage field incorrect")
	}
	if cek.Sig2Usage != KEY_USAGE_TYPE_INVALID {
		return errors.New("cek.cert sig_1_usage field incorrect")
	}

	// verify
	if err = VerifyCert(hrk, hrk); err != nil {
		return errors.Wrap(err, "hrk pubkey verify hrk cert failed")
	}
	if err = VerifyCert(hrk, hsk); err != nil {
		return errors.Wrap(err, "hrk pubkey verify hsk cert failed")
	}
	if err = VerifyCert(hsk, cek); err != nil {
		return errors.Wrap(err, "hsk pubkey verify cek cert failed")
	}
	if err = VerifyCert(cek, pek); err != nil {
		return errors.Wrap(err, "cek pubkey verify pek cert failed")
	}
	return nil
}

func LoadHrkCert() (*ChipRootCert, error) {
	data, err := request("https://cert.hygon.cn/hrk")
	if err != nil {
		return nil, errors.Wrap(err, "download hsk_cek failed")
	}
	if len(data) != ChipRootCertSize {
		return nil, errors.New("invalid hsk_cek content")
	}
	return (*ChipRootCert)(unsafe.Pointer(&data[0])), nil
}

func LoadHskCekCert(chipID string) (*HskCekCert, error) {
	data, err := request(fmt.Sprintf("https://cert.hygon.cn/hsk_cek?snumber=%s", chipID))
	if err != nil {
		return nil, errors.Wrap(err, "download hsk_cek failed")
	}
	if len(data) != HskCekCertSize {
		return nil, errors.New("invalid hsk_cek content")
	}
	return (*HskCekCert)(unsafe.Pointer(&data[0])), nil
}

var request = doRequest

func doRequest(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, errors.Wrap(err, "request failed")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("request failed, status: %d", resp.StatusCode)
	}
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(resp.Body)
}
