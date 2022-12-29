package security

import (
	"context"
	"net"
)

type contextKey struct{ key string }

var netConnContextKey = contextKey{key: "net.conn"}

func ConnContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, netConnContextKey, c)
}
func GetConn(ctx context.Context) (net.Conn, bool) {
	v := ctx.Value(netConnContextKey)
	if v == nil {
		return nil, false
	}

	nc, ok := v.(net.Conn)
	return nc, ok
}
