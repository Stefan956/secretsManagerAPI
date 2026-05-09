.PHONY: test unit-test integration-test e2e-test e2e-cleanup

CLUSTER_NAME    ?= e2e
KUBECONFIG_FILE  = kind-kubeconfig

unit-test:
	go test $$(go list ./... | grep -v -E '(/tests/integration|/tests/e2e)') -v

integration-test:
	go test ./tests/integration -v -count=1

e2e-test:
	kind create cluster --name $(CLUSTER_NAME) --wait 60s
	kind get kubeconfig --name $(CLUSTER_NAME) > $(KUBECONFIG_FILE)
	KUBECONFIG=$(CURDIR)/$(KUBECONFIG_FILE) RUN_E2E=true \
		go test ./tests/e2e -v -run TestE2E_UserAndSecretFlows; \
		EXIT=$$?; kind delete cluster --name $(CLUSTER_NAME); rm -f $(KUBECONFIG_FILE); exit $$EXIT

e2e-cleanup:
	kind delete cluster --name $(CLUSTER_NAME) || true
	rm -f $(KUBECONFIG_FILE)

test: unit-test integration-test
