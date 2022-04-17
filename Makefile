
test: protobuf
	go test --race ./...

protobuf:
	cd ./internal/protocol && ./build.sh

docker: protobuf
	docker build -t diet256:local .

install:
	go install ./cmd/diet256

build:
	go build -o ./out/diet256 ./cmd/diet256

docker-push: docker
	./etc/push.sh

