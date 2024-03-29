
test: protobuf
	go test --race ./...

testv: protobuf
	go test --race -v ./...

protobuf:
	cd ./internal/protocol && ./build.sh

docker: protobuf
	docker build -t diet256:local .

install:
	go install ./cmd/diet256

diet256_linux_amd64:
	GOOS=linux GOARCH=amd64 etc/build_go_binary.sh out/diet256_linux_amd64_${TAG} ./cmd/diet256

diet256_darwin_amd64:
	GOOS=darwin GOARCH=amd64 etc/build_go_binary.sh out/diet256_darwin_amd64_${TAG} ./cmd/diet256

build: diet256_linux_amd64 diet256_darwin_amd64

docker-push: docker
	./etc/push.sh

clean:
	rm ./out/*

