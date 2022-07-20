FROM --platform=${BUILDPLATFORM} golang:alpine as compiler
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0

WORKDIR /go/src/ls3

COPY . .

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go install -ldflags="-s -w" github.com/relvacode/ls3/cmd/ls3


FROM --platform=${TARGETPLATFORM} alpine
ENV LISTEN_ADDRESS=0.0.0.0:80
COPY --from=compiler /go/bin/ls3 /bin/ls3

ENTRYPOINT ["/bin/ls3"]