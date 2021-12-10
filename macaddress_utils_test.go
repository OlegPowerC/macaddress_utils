package macaddress_utils

import (
	"testing"
)

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

func TestHEXStringTo6Bytes(t *testing.T) {
	Errc, Mac6bt := HEXStringTo6Bytes("C0-67-AF-2B-0C-20")
	if Errc != nil {
		t.Error("Корректный MAC адрес, функция вернула ошибку")
	}
	MacBart := make([]byte, 0)
	MacBart = append(MacBart, Mac6bt[0], Mac6bt[1], Mac6bt[2], Mac6bt[3], Mac6bt[4], Mac6bt[5])
	if Mac6bt[0] != 0xc0 || Mac6bt[1] != 0x67 || Mac6bt[2] != 0xaf || Mac6bt[3] != 0x2b || Mac6bt[4] != 0x0c || Mac6bt[5] != 0x20 {
		t.Error("Корректный MAC адрес, функция вернула не корректный:")
	}

	Errc, Mac6bt = HEXStringTo6Bytes("c067.Af2B.0C20")
	if Errc != nil {
		t.Error("Корректный MAC адрес, функция вернула ошибку")
	}
	MacBart = make([]byte, 0)
	MacBart = append(MacBart, Mac6bt[0], Mac6bt[1], Mac6bt[2], Mac6bt[3], Mac6bt[4], Mac6bt[5])
	if Mac6bt[0] != 0xc0 || Mac6bt[1] != 0x67 || Mac6bt[2] != 0xaf || Mac6bt[3] != 0x2b || Mac6bt[4] != 0x0c || Mac6bt[5] != 0x20 {
		t.Error("Корректный MAC адрес, функция вернула не корректный:")
	}
}
