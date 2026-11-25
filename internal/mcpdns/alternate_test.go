package mcpdns

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
)

func TestAnswerValidation(t *testing.T) {
	h := "mcp.linear.app"
	const cname = `{"type":5,"name":"mcp.linear.app.","data":"edge.example."}`
	const ip = `{"type":1,"name":"EDGE.EXAMPLE.","data":"1.2.3.4"}`
	for _, tc := range []struct {
		answer string
		valid  bool
	}{
		{cname + "," + ip, true},
		{cname + "," + ip + `,{"type":1,"name":"edge.example.","data":"127.0.0.1"}`, false},
		{cname + `,{"type":1,"name":"unrelated.example.","data":"8.8.8.8"}`, false},
		{cname + `,{"type":5,"name":"edge.example.","data":"mcp.linear.app."}`, false},
		{cname + `,{"type":28,"name":"edge.example.","data":"2606:4700:4700::1111"}`, false},
	} {
		body := fmt.Sprintf(`{"Status":0,"TC":false,"Question":[{"name":"mcp.linear.app.","type":1}],"Answer":[%s]}`, tc.answer)
		got, err := parseAnswer([]byte(body), h, 1)
		if (err == nil) != tc.valid || (tc.valid && !slices.Equal(got, []netip.Addr{netip.MustParseAddr("1.2.3.4")})) {
			t.Fatal(got, err)
		}
	}
}
