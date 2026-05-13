BIN       ?= fsa-mock
REGISTRY  ?= ghcr.io
REPO      ?= bsv9/fsa-mock
TAG       ?= latest
IMAGE     ?= $(REGISTRY)/$(REPO):$(TAG)
PLATFORMS ?= linux/amd64,linux/arm64

.PHONY: build run test image image-multiarch push login clean

build:
	go build -o bin/$(BIN) ./cmd/fsa-mock

run: build
	FSA_ADDR=:8080 ./bin/$(BIN)

test:
	go test ./...

image:
	podman build -t $(IMAGE) -f Containerfile .

image-multiarch:
	podman build --platform=$(PLATFORMS) --manifest $(IMAGE) -f Containerfile .

login:
	@echo "$$GHCR_TOKEN" | podman login $(REGISTRY) -u $(GHCR_USER) --password-stdin

push: image
	podman push $(IMAGE)

push-multiarch: image-multiarch
	podman manifest push --all $(IMAGE) docker://$(IMAGE)

clean:
	rm -rf bin
