package ls3

import (
	"net/http"
	"time"
)

// bucketCreationDate is a constant date where all buckets were "Created".
// We don't actually know when the bucket was created, but some API consumers can't handle a missing date.
var bucketCreationDate = time.Date(2022, 01, 01, 00, 00, 00, 0, time.UTC)

func (s *Server) ListBuckets(ctx *RequestContext) *Error {
	type Bucket struct {
		CreationDate time.Time
		Name         string
	}
	type ListAllMyBucketsResult struct {
		Buckets struct {
			Bucket []Bucket
		}
	}

	if err := EvaluatePolicy(ListAllMyBuckets, "", ctx.Identity.ACL, ctx); err != nil {
		return err
	}

	buckets, err := s.buckets.ListBuckets()
	if err != nil {
		return ErrorFrom(err)
	}

	var result ListAllMyBucketsResult
	result.Buckets.Bucket = make([]Bucket, 0, len(buckets))

	for _, name := range buckets {
		result.Buckets.Bucket = append(result.Buckets.Bucket, Bucket{
			CreationDate: bucketCreationDate,
			Name:         name,
		})
	}

	ctx.SendXML(http.StatusOK, &result)
	return nil
}
