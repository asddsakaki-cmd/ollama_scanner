// Package errors demonstrates modern Go error handling patterns
package errors

import (
	"errors"
	"fmt"
)

// Sentinel errors for common conditions
var (
	ErrInvalidTarget       = errors.New("invalid target specified")
	ErrTimeout             = errors.New("operation timed out")
	ErrConnectionRefused   = errors.New("connection refused")
	ErrPermissionDenied    = errors.New("permission denied")
	ErrScanInterrupted     = errors.New("scan interrupted")
)

// ScanError is a custom error type for scan failures
type ScanError struct {
	Host  string
	Port  int
	Op    string
	Cause error
}

func (e *ScanError) Error() string {
	return fmt.Sprintf("scan %s on %s:%d failed: %v", e.Op, e.Host, e.Port, e.Cause)
}

func (e *ScanError) Unwrap() error {
	return e.Cause
}

// UserError is displayed to end users
type UserError struct {
	Code    string
	Title   string
	Message string
	Suggest string
	Cause   error
}

func (e *UserError) Error() string {
	var parts []string
	
	if e.Code != "" {
		parts = append(parts, fmt.Sprintf("[%s]", e.Code))
	}
	
	if e.Title != "" {
		parts = append(parts, e.Title)
	} else {
		parts = append(parts, "Error")
	}
	
	parts = append(parts, ": ", e.Message)
	
	if e.Suggest != "" {
		parts = append(parts, fmt.Sprintf("\n\nSuggestion: %s", e.Suggest))
	}
	
	if e.Cause != nil {
		parts = append(parts, fmt.Sprintf("\n\nTechnical details: %v", e.Cause))
	}
	
	return fmt.Sprint(parts...)
}

func (e *UserError) Unwrap() error {
	return e.Cause
}

// Helper functions

// Wrap adds context to an error
func Wrap(err error, context string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", context, err)
}

// Wrapf adds formatted context to an error
func Wrapf(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", fmt.Sprintf(format, args...), err)
}

// Predefined user errors

func InvalidTargetError(target string, cause error) *UserError {
	return &UserError{
		Code:    "E001",
		Title:   "Invalid Target",
		Message: fmt.Sprintf("The target %q is not valid", target),
		Suggest: "Please provide a valid IP address (e.g., 192.168.1.1) or hostname",
		Cause:   cause,
	}
}

func TimeoutError(operation string, duration interface{}, cause error) *UserError {
	return &UserError{
		Code:    "E003",
		Title:   "Operation Timeout",
		Message: fmt.Sprintf("%s timed out after %v", operation, duration),
		Suggest: "Try increasing the timeout with --timeout flag",
		Cause:   cause,
	}
}
