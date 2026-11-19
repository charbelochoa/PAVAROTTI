FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /pavarotti .

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /pavarotti /usr/local/bin/pavarotti
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/pavarotti"]
