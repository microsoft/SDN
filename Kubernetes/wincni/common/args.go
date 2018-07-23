// Copyright Microsoft Corp.
// All rights reserved.

package common

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Argument represents a command line argument.
type Argument struct {
	Name         string
	Shorthand    string
	Description  string
	Type         string
	DefaultValue interface{}
	Value        interface{}
	ValueMap     map[string]interface{}
	strVal       string
	boolVal      bool
}

// ArgumentList represents a set of command line arguments.
type ArgumentList []*Argument

var argList *ArgumentList
var usageFunc func()

// ParseArgs parses and validates command line arguments based on rules in the given ArgumentList.
func ParseArgs(args *ArgumentList, usage func()) {
	argList = args
	usageFunc = usage

	// Setup all arguments.
	for _, arg := range *args {
		switch arg.Type {
		case "bool":
			flag.BoolVar(&arg.boolVal, arg.Name, arg.DefaultValue.(bool), arg.Description)
			flag.BoolVar(&arg.boolVal, arg.Shorthand, arg.DefaultValue.(bool), arg.Description)
		case "int", "string":
			flag.StringVar(&arg.strVal, arg.Name, arg.DefaultValue.(string), arg.Description)
			flag.StringVar(&arg.strVal, arg.Shorthand, arg.DefaultValue.(string), arg.Description)
		}
	}

	// Parse the flag set.
	flag.Usage = printHelp
	flag.Parse()

	// Validate arguments and convert them to their mapped values.
	for _, arg := range *args {
		switch arg.Type {
		case "bool":
			arg.Value = arg.boolVal
		case "string":
			if arg.ValueMap == nil {
				// Argument is a free-form string.
				arg.Value = arg.strVal
			} else {
				// Argument must match one of the values in the map.
				arg.strVal = strings.ToLower(arg.strVal)
				arg.Value = arg.strVal
				if arg.ValueMap[arg.strVal] == nil {
					printErrorForArg(arg)
				}
			}
		case "int":
			if arg.ValueMap == nil {
				// Argument is a free-form integer.
				arg.Value, _ = strconv.Atoi(arg.strVal)
			} else {
				// Argument must match one of the values in the map.
				arg.strVal = strings.ToLower(arg.strVal)
				arg.Value = arg.ValueMap[arg.strVal]
				if arg.Value == nil {
					printErrorForArg(arg)
				}
			}
		}
	}
}

// GetArg returns the parsed value of the given argument.
func GetArg(name string) interface{} {
	for _, arg := range *argList {
		if arg.Name == name {
			return arg.Value
		}
	}
	return nil
}

// printErrorForArg prints the error line for the given argument.
func printErrorForArg(arg *Argument) {
	fmt.Printf("Invalid value '%v' for argument '%v'.\n\n", arg.strVal, arg.Name)
	flag.Usage()
	os.Exit(1)
}

// printHelpForArg prints the help line for the given argument.
func printHelpForArg(arg *Argument) {
	left := fmt.Sprintf("  -%v, --%v", arg.Shorthand, arg.Name)
	right := fmt.Sprintf("%v", arg.Description)

	if arg.ValueMap != nil {
		left += fmt.Sprintf("=%v", arg.DefaultValue)

		var values []string
		for k := range arg.ValueMap {
			values = append(values, k)
		}
		right += " {" + strings.Join(values, ",") + "}"
	}

	fmt.Printf("%-30v %v\n", left, right)
}

// printHelp prints help and usage information for the argument list.
func printHelp() {
	usageFunc()
	fmt.Printf("\nUsage: %v [OPTIONS]\n\n", os.Args[0])
	fmt.Printf("Options:\n")

	for _, arg := range *argList {
		printHelpForArg(arg)
	}

	// -h is implicit.
	printHelpForArg(&Argument{
		Name:        "help",
		Shorthand:   "h",
		Description: "Print usage information"})
}
