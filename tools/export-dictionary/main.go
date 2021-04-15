package main

import (
	"fmt"
	"saasreconn/internal/zonewalk"
)

func main() {

	dictionary := make(chan string)
	go zonewalk.BuildLocalDictionary("", dictionary)
	for {
		guess, more := <-dictionary
		if !more {
			break
		}
		fmt.Println(guess)
	}
}
