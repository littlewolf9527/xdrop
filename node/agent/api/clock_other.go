//go:build !linux

package api

import "errors"

func hitsClock() (uint64, error) {
	return 0, errors.New("rules/hits requires Linux CLOCK_MONOTONIC_COARSE")
}
