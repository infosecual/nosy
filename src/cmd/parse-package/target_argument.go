package main

import (
	"fmt"
)

type TargetArgument struct {
	Name string
	Type string
	// 0 == not ptr, 1 == *, 2 == **
	Pointer int
	Array   bool
}

func (a TargetArgument) IsIncludable() bool {
	// built-ins supported w/ vanilla go v1.18+:
	//      string, []byte, int, int8, int16, int32/rune, int64, uint,
	//      uint8/byte, uint16 , uint32, uint64, float32, float64, bool
	/*
	   supported_types := []string{"string", "byte", "[]byte", "int", "int8",
	                               "int16", "int32", "rune", "int64", "uint",
	                               "uint8", "byte", "uint16", "uint32", "uint64",
	                               "float32", "float64", "bool"}
	*/
	// ignore "stubs"
	//if a.Name == "_" {
	//	return false
	//}

	// return true if in the supported arg list, else false
	/*
		    for _, supported := range supported_types {
				if supported == a.Type {
					return true
				}
			}
	*/
	return true
}

// pretty print TargetArgument for debugging purposes
func (a TargetArgument) Print() {
	fmt.Println("#################################################")
	fmt.Println("# argument: \t", a.Type)
	fmt.Println("# pointer: \t", a.Pointer)
	fmt.Println("# array: \t", a.Array)
	fmt.Println("#################################################")
	fmt.Println()
	return
}
