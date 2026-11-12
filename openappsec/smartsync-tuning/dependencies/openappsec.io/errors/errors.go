package errors

import (
	"fmt"

	"golang.org/x/xerrors"
)

// Severity level
type Severity string

// Severity level consts
const (
	Critical Severity = "Critical"
	High     Severity = "High"
	Medium   Severity = "Medium"
	Low      Severity = "Low"
	Info     Severity = "Info"
)

// Class defines an errors behavior
type Class int

const (
	// ClassUnknown default Class
	ClassUnknown Class = iota
	// ClassBadInput for bad input errors
	ClassBadInput
	// ClassForbidden for forbidden actions
	ClassForbidden
	// ClassNotFound for resources that are not existent
	ClassNotFound
	// ClassInternal for internal errors
	ClassInternal
	// ClassUnauthorized for unauthorized actions
	ClassUnauthorized
	// ClassBadGateway for server bad gateway response
	ClassBadGateway
)

// Err represents a single error.
type Err struct {
	err     error
	label   string
	class   Class
	code    code
	details interface{}
}

// Error is our version of the error interface, exposing the regular error capabilities alongside the ability to set class, label and details.
type Error interface {
	error
	SetLabel(label string) Error
	SetClass(c Class) Error
	SetDetails(details interface{}) Error
	Unwrap() error
}

// New creates a new error
func New(message string) Error {
	return &Err{
		err: xerrors.New(message),
	}
}

// Wrap wraps an existing error in more contextual information
func Wrap(err error, message string) Error {
	if err == nil {
		return &Err{
			err: xerrors.New(message),
		}
	}

	return &Err{
		err: xerrors.Errorf("%s: %w", message, err),
	}
}

// Wrapf wraps an existing error in more contextual information and allow for format operations
func Wrapf(err error, message string, a ...interface{}) Error {
	if err == nil {
		return &Err{
			err: xerrors.Errorf("%s", fmt.Sprintf(message, a...)),
		}
	}

	return &Err{
		err: xerrors.Errorf("%s: %w", fmt.Sprintf(message, a...), err),
	}
}

// Errorf creates a new error using a formatted string
func Errorf(format string, a ...interface{}) Error {
	return &Err{
		err: xerrors.Errorf(format, a...),
	}
}

// SetClass set the error's Class, the Class defines the errors behavior
func (e *Err) SetClass(class Class) Error {
	e.class = class
	return e
}

// GetClass get the error's Class, the Class defines the errors behavior
func (e *Err) GetClass() Class {
	return e.class
}

// SetLabel set the error's Label, with the Label it's possible to distinguish between errors of the same class
func (e *Err) SetLabel(label string) Error {
	e.label = label
	return e
}

// SetDetails set the error's Details, which can provide more information on the error.
func (e *Err) SetDetails(details interface{}) Error {
	e.details = details
	return e
}

// Error returns the message from within an error
func (e *Err) Error() string {
	return e.err.Error()
}

// Unwrap returns the underlying error of the Err struct
func (e *Err) Unwrap() error {
	return e.err
}

// IsClass checks whether an error, or any of the errors wrapped within it, is of a given Class
func IsClass(err error, class Class) bool {
	if err == nil {
		return false
	}

	e, ok := err.(*Err)
	if !ok {
		return false
	}
	if e.class == class {
		return true
	}
	return IsClass(xerrors.Unwrap(e.err), class)
}

// IsClassTopLevel checks whether an error, or any of the errors wrapped within it, which has a defined
// class, is of a given Class.
func IsClassTopLevel(err error, class Class) bool {
	if err == nil {
		return false
	}

	e, ok := err.(*Err)
	if !ok {
		return false
	}
	if e.class == ClassUnknown {
		return IsClassTopLevel(xerrors.Unwrap(e.err), class)
	}
	return e.class == class
}

// IsLabel checks whether a label, or any of the errors wrapped within it, is of a given Label
func IsLabel(err error, label string) bool {
	if err == nil {
		return false
	}

	e, ok := err.(*Err)
	if !ok {
		return false
	}
	if e.label == label {
		return true
	}
	return IsLabel(xerrors.Unwrap(e.err), label)
}

// GetTopLabel returns the error's top label
func GetTopLabel(err error) string {
	e, ok := err.(*Err)
	if !ok {
		return ""
	}

	if e.label != "" {
		return e.label
	}

	return GetTopLabel(xerrors.Unwrap(e.err))
}

// GetDetails returns the error's top details
func GetDetails(err error) interface{} {
	e, ok := err.(*Err)
	if !ok {
		return ""
	}

	if e.details != nil {
		return e.details
	}

	return GetDetails(xerrors.Unwrap(e.err))
}
