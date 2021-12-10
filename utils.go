package macaddress_utils

import (
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const MACFORMAT_XXXXdotXXXXdotXXXX = 1
const MACFORMAT_XXXXcolonXXXXcolonXXXX = 2
const MACFORMAT_XXXXdashXXXXdashXXXX = 3
const MACFORMAT_XXdotXXdotXXdotXXdotXXdotXX = 4
const MACFORMAT_XXcolonXXcolonXXcolonXXcolonXXcolonXX = 5
const MACFORMAT_XXdashXXdashXXdashXXdashXXdashXXdash = 6

func SNMPMACfrom6bytestoHexString(snmpmacaddr [6]byte, delimiterpattern int) (error, string) {
	var byteslice []byte
	byteslice = make([]byte, 6)
	for ind, _ := range snmpmacaddr {
		byteslice[ind] = snmpmacaddr[ind]
	}
	err, retstring := SNMPMACtoHexStringFromByteArray(byteslice, delimiterpattern)
	return err, retstring
}

func SNMPMACtoHexString(snmpmacaddr string, delimiterpattern int) (error, string) {
	slicetxt := strings.Split(snmpmacaddr, ".")
	if len(slicetxt) != 6 {
		return errors.New("Invalid MAC address string, must be XX.XX.XX.XX.XX.XX"), ""
	}
	var macbytes []byte
	macbytes = make([]byte, 6)
	for ind, bs := range slicetxt {

		ier, iererr := hex.DecodeString(bs)
		if iererr != nil {
			return fmt.Errorf("Invalid MAC address string: %s", iererr), ""
		} else {
			if len(ier) > 1 {
				return errors.New("Invalid MAC address string, must be XX.XX.XX.XX.XX.XX"), ""
			}
		}
		macbytes[ind] = ier[0]
	}
	retstring := hex.EncodeToString(macbytes)
	switch delimiterpattern {
	case 1:
		retstring = retstring[:4] + "." + retstring[4:8] + "." + retstring[8:]
		break
	case 2:
		retstring = retstring[:4] + ":" + retstring[4:8] + ":" + retstring[8:]
		break
	case 3:
		retstring = retstring[:4] + "-" + retstring[4:8] + "-" + retstring[8:]
		break
	case 4:
		retstring = retstring[:2] + "." + retstring[2:4] + "." + retstring[4:6] + "." + retstring[6:8] + "." + retstring[8:10] + "." + retstring[10:]
		break
	case 5:
		retstring = retstring[:2] + ":" + retstring[2:4] + ":" + retstring[4:6] + ":" + retstring[6:8] + ":" + retstring[8:10] + ":" + retstring[10:]
		break
	case 6:
		retstring = retstring[:2] + "-" + retstring[2:4] + "-" + retstring[4:6] + "-" + retstring[6:8] + "-" + retstring[8:10] + "-" + retstring[10:]
		break
	default:
		return errors.New("Invalid delimiter index"), ""
		break
	}
	return nil, retstring
}

func SNMPMACtoHexStringFromByteArray(bytearray []byte, delimiterpattern int) (error, string) {
	retstring := hex.EncodeToString(bytearray)
	switch delimiterpattern {
	case 1:
		retstring = retstring[:4] + "." + retstring[4:8] + "." + retstring[8:]
		break
	case 2:
		retstring = retstring[:4] + ":" + retstring[4:8] + ":" + retstring[8:]
		break
	case 3:
		retstring = retstring[:4] + "-" + retstring[4:8] + "-" + retstring[8:]
		break
	case 4:
		retstring = retstring[:2] + "." + retstring[2:4] + "." + retstring[4:6] + "." + retstring[6:8] + "." + retstring[8:10] + "." + retstring[10:]
		break
	case 5:
		retstring = retstring[:2] + ":" + retstring[2:4] + ":" + retstring[4:6] + ":" + retstring[6:8] + ":" + retstring[8:10] + ":" + retstring[10:]
		break
	case 6:
		retstring = retstring[:2] + "-" + retstring[2:4] + "-" + retstring[4:6] + "-" + retstring[6:8] + "-" + retstring[8:10] + "-" + retstring[10:]
		break
	default:
		return errors.New("Invalid delimiter index"), ""
	}
	return nil, retstring
}

func HEXStringTo6Bytes(Hexstring string) (err error, MacAddr [6]byte) {
	var MacAddrResult [6]byte
	MACstring := strings.ToLower(Hexstring)
	MACstring = strings.ReplaceAll(MACstring, "-", "")
	MACstring = strings.ReplaceAll(MACstring, ".", "")
	MACstring = strings.ReplaceAll(MACstring, ":", "")
	matched, matcherr := regexp.MatchString(`^[0-9a-f]{12}$`, MACstring)
	if matcherr == nil && matched {
		MacInBytes, MacInBytesErr := hex.DecodeString(MACstring)
		if MacInBytesErr != nil {
			return MacInBytesErr, MacAddrResult
		}
		if len(MacInBytes) != 6 {
			return fmt.Errorf("Error in len of the MAC addrress"), MacAddrResult
		} else {
			for Bcounter, Cbyte := range MacInBytes {
				MacAddrResult[Bcounter] = Cbyte
			}
			return nil, MacAddrResult
		}
	} else {
		return fmt.Errorf("Error in MAC addrress string"), MacAddrResult
	}
}
