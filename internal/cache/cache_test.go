package cache

import (
	"strings"
	"testing"
)

func TestMergeCachedZoneLists(t *testing.T) {
	zoneList1 := CachedZoneList{
		Names: []string{"A", "B"},
		Prev:  []string{"AA", "BB"},
		Next:  []string{"AB", "BC"},
	}
	zoneList2 := CachedZoneList{
		Names: []string{"A", "C"},
		Prev:  []string{"AA", "CC"},
		Next:  []string{"AB", "CD"},
	}
	expectedMergedZoneList := CachedZoneList{
		Names: []string{"A", "B", "C"},
		Prev:  []string{"AA", "BB", "CC"},
		Next:  []string{"AB", "BC", "CD"},
	}

	resultZoneList := MergeCachedZoneLists(zoneList1, zoneList2)
	if strings.Join(resultZoneList.Names, ",") != strings.Join(expectedMergedZoneList.Names, ",") {
		t.Errorf("[cache/MergeCachedZoneLists.Names] got %s, expected %s", strings.Join(resultZoneList.Names, ","), strings.Join(expectedMergedZoneList.Names, ","))
	}
	if strings.Join(resultZoneList.Prev, ",") != strings.Join(expectedMergedZoneList.Prev, ",") {
		t.Errorf("[cache/MergeCachedZoneLists.Prev] got %s, expected %s", strings.Join(resultZoneList.Prev, ","), strings.Join(expectedMergedZoneList.Prev, ","))
	}
	if strings.Join(resultZoneList.Next, ",") != strings.Join(expectedMergedZoneList.Next, ",") {
		t.Errorf("[cache/MergeCachedZoneLists.Next] got %s, expected %s", strings.Join(resultZoneList.Next, ","), strings.Join(expectedMergedZoneList.Next, ","))
	}
}
