package identity

import (
	"fmt"
	"strings"
)

func (s *SQLIdentityStore) placeholder(position int) string {
	if s.driver == "postgres" {
		return fmt.Sprintf("$%d", position)
	}
	return "?"
}

func (s *SQLIdentityStore) placeholders(count int) string {
	values := make([]string, 0, count)
	for i := 1; i <= count; i++ {
		values = append(values, s.placeholder(i))
	}
	return strings.Join(values, ", ")
}
