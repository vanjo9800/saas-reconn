package cache

func MergeCachedZoneLists(list1 CachedZoneList, list2 CachedZoneList) (result CachedZoneList) {
	// list1 and list2 must be sorted
	result = CachedZoneList{
		Names: []string{},
		Prev:  []string{},
		Next:  []string{},
	}

	index1, index2 := 0, 0
	for index1 < len(list1.Names) && index2 < len(list2.Names) {
		if list1.Names[index1] == list2.Names[index2] {
			result.Names = append(result.Names, list1.Names[index1])
			result.Prev = append(result.Prev, list1.Prev[index1])
			result.Next = append(result.Next, list1.Next[index1])
			index1++
			index2++
		} else if list1.Names[index1] < list2.Names[index2] {
			result.Names = append(result.Names, list1.Names[index1])
			result.Prev = append(result.Prev, list1.Prev[index1])
			result.Next = append(result.Next, list1.Next[index1])
			index1++
		} else {
			result.Names = append(result.Names, list2.Names[index2])
			result.Prev = append(result.Prev, list2.Prev[index2])
			result.Next = append(result.Next, list2.Next[index2])
			index2++
		}
	}

	for index1 < len(list1.Names) {
		result.Names = append(result.Names, list1.Names[index1])
		result.Prev = append(result.Prev, list1.Prev[index1])
		result.Next = append(result.Next, list1.Next[index1])
		index1++
	}
	for index2 < len(list2.Names) {
		result.Names = append(result.Names, list2.Names[index2])
		result.Prev = append(result.Prev, list2.Prev[index2])
		result.Next = append(result.Next, list2.Next[index2])
		index2++
	}

	return result
}
