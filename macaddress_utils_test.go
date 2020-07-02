package macaddress_utils

import "testing"

func TestSNMPMACfrom6bytestoHexString(t *testing.T) {
	Testmac := [6]byte{0x0f, 0x77, 0x8f, 0xa0, 0xb7, 0xf5}

	ErrorInMAC, MACStr := SNMPMACfrom6bytestoHexString(Testmac, MACFORMAT_XXcolonXXcolonXXcolonXXcolonXXcolonXX)
	if ErrorInMAC != nil {
		t.Error("Ожидается успешое завершение, а получена ошибка:", ErrorInMAC)
	} else {
		if len(MACStr) != 17 {
			t.Error("Ожидается длина строки 18 а получена:", len(MACStr))
		}
	}

	ErrorInMAC, MACStr = SNMPMACfrom6bytestoHexString(Testmac, MACFORMAT_XXXXcolonXXXXcolonXXXX)
	if ErrorInMAC != nil {
		t.Error("Ожидается успешое завершение, а получена ошибка:", ErrorInMAC)
	} else {
		if len(MACStr) != 14 {
			t.Error("Ожидается длина строки 18 а получена:", len(MACStr))
		}
	}

	ErrorInMAC, MACStr = SNMPMACfrom6bytestoHexString(Testmac, 78)
	if ErrorInMAC == nil {
		t.Error("Ожидается ошибка:")
	}
}

func TestSNMPMACtoHexString(t *testing.T) {
	Testmacstring := "00.77.6F.5e.89.7c"
	Testmacstring_wrong := []string{"00.77.6F.f117.89.7c", "00.77.6F.89.7c", "00,77.6F-c4.89.7c"}

	ErrorInMAC, MACStr := SNMPMACtoHexString(Testmacstring, MACFORMAT_XXcolonXXcolonXXcolonXXcolonXXcolonXX)
	if ErrorInMAC != nil {
		t.Error("Ожидается успешое завершение, а получена ошибка:", ErrorInMAC)
	} else {
		if len(MACStr) != 17 {
			t.Error("Ожидается длина строки 18 а получена:", len(MACStr))
		}
	}

	ErrorInMAC, MACStr = SNMPMACtoHexString(Testmacstring, MACFORMAT_XXXXcolonXXXXcolonXXXX)
	if ErrorInMAC != nil {
		t.Error("Ожидается успешое завершение, а получена ошибка:", ErrorInMAC)
	} else {
		if len(MACStr) != 14 {
			t.Error("Ожидается длина строки 18 а получена:", len(MACStr))
		}
	}

	ErrorInMAC, MACStr = SNMPMACtoHexString(Testmacstring, 78)
	if ErrorInMAC == nil {
		t.Error("Ожидается ошибка:")
	}

	ErrorInMAC, MACStr = SNMPMACtoHexString(Testmacstring_wrong[0], MACFORMAT_XXXXcolonXXXXcolonXXXX)
	if ErrorInMAC == nil {
		t.Error("Ожидается ошибка:")
	}
}
