package db

import "sort"

func DomainNamesDiff(old []string, new []string) []string {
	sort.Strings(old)
	sort.Strings(new)

	resultDiff := []string{}
	oldIndex := 0
	newIndex := 0
	for oldIndex < len(old) && newIndex < len(new) {
		if old[oldIndex] < new[newIndex] {
			append(resultDiff, "-:"+old[oldIndex])
			oldIndex++
			continue
		}

		if old[oldIndex] > new[newIndex] {
			append(resultDiff, "+:"+new[newIndex])
			newIndex++
			continue
		}

		oldIndex++
		newIndex++
	}
	for oldIndex < len(old) {
		append(resultDiff, "-:"+old[oldIndex])
		oldIndex++
	}
	for newIndex < len(new) {
		append(resultDiff, "+:"+new[newIndex])
		newIndex++
	}

	return resultDiff
}
