FROM golang:1.18-alpine3.14 as builder
RUN apk update && apk add git
RUN mkdir /input && mkdir /output
WORKDIR /input

COPY go.mod go.sum /input
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /output/diet256 ./cmd/diet256

FROM alpine:3.14
COPY --from=builder /output/diet256 .
ENTRYPOINT ["./diet256"]
