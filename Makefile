# Define Docker related variables.
REGISTRY ?= projectsveltos
IMAGE_NAME ?= prepare-pullmode

export CONTROLLER_IMG ?= $(REGISTRY)/$(IMAGE_NAME)

KIND := ../../hack/tools/bin/kind


.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	docker build --load --build-arg BUILDOS=linux --build-arg TARGETARCH=amd64 -t $(CONTROLLER_IMG):latest .


.PHONY: load-image
load-image: docker-build $(KIND)
	$(KIND) load docker-image $(CONTROLLER_IMG):$(TAG) --name $(CONTROL_CLUSTER_NAME)