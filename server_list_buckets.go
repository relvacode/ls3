package ls3

import (
	"net/http"
)

func (s *Server) ListBuckets(ctx *RequestContext) *Error {
	type Bucket struct {
		Name string
	}
	type ListAllMyBucketsResult struct {
		Buckets struct {
			Bucket []Bucket
		}
	}

	buckets, err := s.buckets.ListBuckets()
	if err != nil {
		return ErrorFrom(err)
	}

	var result ListAllMyBucketsResult
	result.Buckets.Bucket = make([]Bucket, 0, len(buckets))

	for _, name := range buckets {
		result.Buckets.Bucket = append(result.Buckets.Bucket, Bucket{
			Name: name,
		})
	}

	ctx.SendXML(http.StatusOK, &result)
	return nil
}
