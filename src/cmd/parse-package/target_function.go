package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/types"
)

type TargetFunction struct {
	Name     string
	IsMethod bool
	Receiver string
	//StructType string
	Args        []TargetArgument
	PackageName string
	PackagePath string
	PackageDir  string
	TypesFunc   *types.Func // func info from go/types library
}

func IsInterfaceReceiver(func_decl *types.Func) bool {
	func_signature, ok := func_decl.Type().(*types.Signature)
	// check if func decl is a signature type
	if !ok {
		return false
	}
	if func_signature.Recv() == nil {
		return false
	}
	_, ok = func_signature.Recv().Type().(*types.Interface)
	if ok {
		return true
	}
	_, ok = func_signature.Recv().Type().Underlying().(*types.Interface)
	return ok
}

// constructorResult expects a *types.Func that is type *types.Signature,
// and returns the *types.Named for the first returned result. It allows
// a single return result or two returned results if the second is of type error.
// Otherwise, constructorResult returns nil.
// If the returned result is a pointer to a named type,
// this returns the named type rather than the pointer.
func constructorResult(f *types.Func) (n *types.Named, secondResultIsErr bool) {
	ctorSig, ok := f.Type().(*types.Signature)
	if !ok {
		return nil, false
	}

	ctorResults := ctorSig.Results()
	if ctorResults.Len() > 2 || ctorResults.Len() == 0 {
		return nil, false
	}

	secondResultIsErr = false
	if ctorResults.Len() == 2 {
		// We allow error type as second return value
		secondResult := ctorResults.At(1)
		_, ok = secondResult.Type().Underlying().(*types.Interface)
		if ok && secondResult.Type().String() == "error" {
			secondResultIsErr = true
		} else {
			return nil, false
		}
	}

	ctorResult := ctorResults.At(0)
	ctorResultN, err := namedType(ctorResult)
	if err != nil {
		// namedType returns a *types.Named if the passed in
		// *types.Var is a named type or a pointer to a named type.
		// This candidate constructor result is neither of those, which means it can't
		// match the named type of a receiver, so this isn't really a valid constructor.
		return nil, false
	}

	return ctorResultN, secondResultIsErr
}

// receiver expects a *types.Func that is type *types.Signature,
// and returns the *types.Named for the receiver if
// f has one, and nil otherwise. If the receiver is a pointer
// to a named type, this returns the named type rather than the pointer.
func receiver(f *types.Func) *types.Named {
	sig, ok := f.Type().(*types.Signature)
	if !ok {
		return nil
	}
	// Get our receiver, which might be nil if we don't have a receiver
	recv := sig.Recv()
	if recv == nil {
		return nil
	}
	n, err := namedType(recv)
	if err != nil {
		return nil
	}
	return n
}

// isConstructor reports if f is a constructor.
// It cannot have a receiver, must return a named type or pointer to named type
// as its first return value, and can optionally have its second return value be type error.
// This is a more narrow definition than for example 'go doc',
// which allows any number of builtin types to be returned in addition to a single named type.
func (f TargetFunction) IsConstructor() bool {
	// ctorResultN will be the named type if the returned type is a pointer to a named type.
	ctorResultN, _ := constructorResult(f.TypesFunc)
	if ctorResultN == nil {
		// Not a named return result, so can't be a constructor.
		return false
	}
	// Constructors do not have receivers.
	return receiver(f.TypesFunc) == nil
}

func (f TargetFunction) IsIncludable(target_config TargetRepoConfig) bool {
	//f.Print()
	if IsInterfaceReceiver(f.TypesFunc) {
		return false
	}

	// prob should add this back in at some point
	//if len(f.Args) == 0 {
	//	return false
	//}

	// if the function name does not start with a capital letter than it is
	// not exported so do not fuzz it it may be desireable to work around this
	// with the same package name delcared in the future
	//if unicode.IsLower(rune(f.Name[0])) {
	//	return false
	//}

	// TODO: remove this
	//if f.IsMethod {
	//	return false
	//}

	// check that the function name is not in the ignore list
	for _, fn := range target_config.IgnoreFunctions {
		if fn == fmt.Sprintf("%s.%s", f.PackageName, f.Name) {
			return false
		}
	}

	for _, arg := range f.Args {
		if !arg.IsIncludable() {
			return false
		}
	}

	return true
}

// since functions can be defined more than once with the same name and
// different function interfaces we need to make a unique wrapper function name
// this function hashes information about the function interface to do so
func (f TargetFunction) UniqueName() string {
	function_interface := "args:"
	if f.IsMethod {
		function_interface += f.Receiver
	}
	for _, arg := range f.Args {
		function_interface += arg.Type
	}
	unique_id := sha256.Sum256([]byte(function_interface))
	return f.Name + "_" + hex.EncodeToString(unique_id[:4])
}

// pretty print TargetFunction for debugging purposes
func (f TargetFunction) Print() {
	fmt.Println("#################################################")
	fmt.Println("# function: \t", f.Name)
	fmt.Println("# is method: \t", f.IsMethod)
	if f.IsMethod == true {
		fmt.Println("# receiver: \t", f.Receiver)
	}

	// if the function has arguments then print them
	if len(f.Args) > 0 {
		for i, arg := range f.Args {
			if i == 0 {
				// handle arrays
				if arg.Array {
					fmt.Printf("# args: \t %s[]\n", arg.Type)
				} else {
					fmt.Printf("# args: \t %s\n", arg.Type)
				}
			} else {
				// handle arrays
				if arg.Array {
					fmt.Printf("#       \t %s[]\n", arg.Type)
				} else {
					fmt.Printf("#       \t %s\n", arg.Type)
				}
			}
		}
	}

	fmt.Println("#################################################")
	fmt.Println()
	return
}
