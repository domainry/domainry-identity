package identity

import (
	"strings"
)

func (s *SQLIdentityStore) placeholder(position int) string {
	return s.sqlRenderer().Placeholder(position)
}

func (s *SQLIdentityStore) placeholders(count int) string {
	values := make([]string, 0, count)
	for i := 1; i <= count; i++ {
		values = append(values, s.placeholder(i))
	}
	return strings.Join(values, ", ")
}
