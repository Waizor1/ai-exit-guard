//go:build !darwin

package main

import (
	"context"
	"errors"
)

func systemIngress(context.Context, string) error { return errors.New("only available on macOS") }
