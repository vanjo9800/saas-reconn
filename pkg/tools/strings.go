package tools

import "strings"

func UniqueStrings(arr []string) []string {
	flags := make(map[string]bool)
	for _, element := range arr {
		flags[element] = true
	}

	var uniqueElements []string
	for element, _ := range flags {
		uniqueElements = append(uniqueElements, element)
	}

	return uniqueElements
}

// NameToPath is a method which escapes a name, so we can use it as a filename
func NameToPath(filename string) string {
	escapedName := filename
	escapedName = strings.ReplaceAll(escapedName, "/|\\| ", "_")

	return escapedName
}
