package zonewalk

import (
	"math/big"
	"saasreconn/internal/cache"
	"testing"
)

func TestNsec3HashToNumber(t *testing.T) {
	sampleHash := "00000000000000000000000000000200"
	expectedNumber := big.NewInt(2048)
	number := nsec3HashToNumber(sampleHash)
	if number.String() != expectedNumber.String() {
		t.Errorf("[Nsec3HashToNumber] expected %s, got %s", expectedNumber, number)
	}
}

func TestCoveredDistance(t *testing.T) {
	sampleHash1 := "00000000000000000000000000000200"
	sampleHash2 := "00000000000000000000000000000220"
	expectedDistance := big.NewInt(64)
	distance := CoveredDistance(sampleHash1, sampleHash2)
	if distance.String() != expectedDistance.String() {
		t.Errorf("[CoveredDistance_simple] expected %s, got %s", expectedDistance, distance)
	}

	sampleHash1 = "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV"
	sampleHash2 = "0000000000000000000000000000001V"
	distance = CoveredDistance(sampleHash1, sampleHash2)
	if distance.String() != expectedDistance.String() {
		t.Errorf("[CoveredDistance_loop] expected %s, got %s", expectedDistance, distance)
	}
}

func TestClosest(t *testing.T) {
	sampleZoneList := CreateZoneList(cache.CachedZoneList{
		Names: []string{
			"CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB2",
			"F3N813QOICKFN71QEURUTGR6FM1N0E9U",
		},
		Prev: []string{
			"F3N813QOICKFN71QEURUTGR6FM1N0E9U",
			"CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB2",
		},
		Next: []string{
			"F3N813QOICKFN71QEURUTGR6FM1N0E9U",
			"CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB2",
		},
	})

	expectedClosest := []string{"", "CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB2", "CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB2"}
	testHashes := []string{"CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB1", "CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB2", "CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB3"}
	for index, val := range testHashes {
		closest := sampleZoneList.Closest(val).Name
		if closest != expectedClosest[index] {
			t.Errorf("[ZoneRecord.Closest] %s : expected %s, got %s", val, expectedClosest[index], closest)
		}
	}
}

func TestCovered(t *testing.T) {
	sampleZoneList := CreateZoneList(cache.CachedZoneList{
		Names: []string{
			"CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB2",
			"EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
			"F3N813QOICKFN71QEURUTGR6FM1N0E9U",
		},
		Prev: []string{
			"F3N813QOICKFN71QEURUTGR6FM1N0E9U",
			"CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB2",
			"",
		},
		Next: []string{
			"EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
			"",
			"CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB2",
		},
	})
	expectedCovered := []bool{
		true,
		true,
		true,
		false,
		true,
		true,
	}
	testHashes := []string{
		"00000000000000000000000000000000",
		"CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB2",
		"CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMVVV",
		"EEEEEEEEEEEEEEEEEEEEEEEEEEEEEVVV",
		"F3N813QOICKFN71QEURUTGR6FM1N0E9U",
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
	}
	for index, val := range testHashes {
		covered := sampleZoneList.Covered(val)
		if covered != expectedCovered[index] {
			t.Errorf("[ZoneRecord.Covered] %s : expected %t, got %t", val, expectedCovered[index], covered)
		}
	}

}

func TestAddRecord(t *testing.T) {
	sampleZoneList := CreateZoneList(cache.CachedZoneList{
		Names: []string{
			"CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB2",
			"F3N813QOICKFN71QEURUTGR6FM1N0E9U",
		},
		Prev: []string{
			"F3N813QOICKFN71QEURUTGR6FM1N0E9U",
			"",
		},
		Next: []string{
			"",
			"CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB2",
		},
	})

	sampleZoneList.AddRecord("CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB2", "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE")
	expectedZoneList := CreateZoneList(cache.CachedZoneList{
		Names: []string{
			"CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB2",
			"EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
			"F3N813QOICKFN71QEURUTGR6FM1N0E9U",
		},
		Prev: []string{
			"F3N813QOICKFN71QEURUTGR6FM1N0E9U",
			"CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB2",
			"",
		},
		Next: []string{
			"EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
			"",
			"CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB2",
		},
	})
	if expectedZoneList.ToString() != sampleZoneList.ToString() {
		t.Errorf("[ZoneRecord.AddRecord_new] expected \n%s, got \n%s", expectedZoneList.ToString(), sampleZoneList.ToString())
	}

	sampleZoneList.AddRecord("F3N813QOICKFN71QEURUTGR6FM1N0E9U", "F3N813QOICKFN71QEURUTGR6FM1N0EVV")
	expectedZoneList = CreateZoneList(cache.CachedZoneList{
		Names: []string{
			"CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB2",
			"EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
			"F3N813QOICKFN71QEURUTGR6FM1N0E9U",
			"F3N813QOICKFN71QEURUTGR6FM1N0EVV",
		},
		Prev: []string{
			"",
			"CJ7AHK7DD7VM7EGEG3G0TCDJP8HGMPB2",
			"",
			"F3N813QOICKFN71QEURUTGR6FM1N0E9U",
		},
		Next: []string{
			"EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE",
			"",
			"F3N813QOICKFN71QEURUTGR6FM1N0EVV",
			"",
		},
	})
	if expectedZoneList.ToString() != sampleZoneList.ToString() {
		t.Errorf("[ZoneRecord.AddRecord_nextUpdate] expected \n%s, got \n%s", expectedZoneList.ToString(), sampleZoneList.ToString())
	}

}
