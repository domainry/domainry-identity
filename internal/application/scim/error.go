package scim

import "fmt"

type Error struct {
	Status   int
	SCIMType string
	Detail   string
	Cause    error
}

func (err *Error) Error() string {
	if err == nil {
		return ""
	}
	if err.Cause != nil {
		return fmt.Sprintf("%s: %v", err.Detail, err.Cause)
	}
	return err.Detail
}

func (err *Error) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

func invalidValue(detail string) error {
	return &Error{Status: 400, SCIMType: "invalidValue", Detail: detail}
}
func invalidFilter(detail string) error {
	return &Error{Status: 400, SCIMType: "invalidFilter", Detail: detail}
}
func invalidPath(detail string) error {
	return &Error{Status: 400, SCIMType: "invalidPath", Detail: detail}
}
func noTarget(detail string) error { return &Error{Status: 400, SCIMType: "noTarget", Detail: detail} }
func conflict(detail string) error {
	return &Error{Status: 409, SCIMType: "uniqueness", Detail: detail}
}
func notFound(detail string) error           { return &Error{Status: 404, Detail: detail} }
func preconditionFailed(detail string) error { return &Error{Status: 412, Detail: detail} }
