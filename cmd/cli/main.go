/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package main

import (
	"crypto_gen/cmd/cli/cmd"
	"crypto_gen/cmd/cli/shared"
)

func main() {
	shared.Version = version
	cmd.Execute()
}

var version = "Development"
