.PHONY: falco-validate falco-test install lint test sast scan run docker tf-init tf-plan tf-apply inventory harden cis audit-before audit-after metrics
VENV ?= .venv
PY := $(VENV)/bin
IMAGE_TAG ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)

install:
	python3 -m venv $(VENV) && $(PY)/pip install -r requirements-dev.txt
lint:
	$(PY)/ruff check . && $(PY)/ruff format --check .
test:
	$(PY)/pytest
sast:
	$(PY)/bandit -r app -ll && pipx run semgrep scan --error --metrics=off --config p/python --config .semgrep/securedeploy.yml app
scan:
	docker build -t securedeploy:$(IMAGE_TAG) . && trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 securedeploy:$(IMAGE_TAG)
run:
	$(PY)/uvicorn app.main:app --reload
docker:
	docker build -t securedeploy:$(IMAGE_TAG) .

tf-init:
	cd terraform && terraform init
tf-plan:
	cd terraform && terraform plan -out tfplan
tf-apply:
	cd terraform && terraform apply tfplan

# Genera ansible/inventory.ini y group_vars/terraform.yml desde los outputs de Terraform
inventory:
	./scripts/gen_inventory.sh
harden:
	cd ansible && ansible-playbook site.yml -e app_image_tag=$(IMAGE_TAG)
cis:
	cd ansible && ansible-galaxy install -r requirements.yml -p .roles && ansible-playbook cis.yml
audit-before:
	cd ansible && ansible-playbook audit.yml -e label=before
audit-after:
	cd ansible && ansible-playbook audit.yml -e label=after
metrics:
	python3 scripts/metrics.py

# Valida sintaxis y campos de las reglas con el binario real de Falco (sin driver ni privilegios)
falco-validate:
	docker run --rm -v $(CURDIR)/detection/falco:/rules:ro falcosecurity/falco-no-driver:0.39.2 \
	  falco -V /rules/securedeploy_rules.yaml
# Dispara cada regla en el host (requiere SSM/SSH al EC2): copia y ejecuta scripts/test_falco.sh con sudo
falco-test:
	@echo "En el EC2: sudo ./scripts/test_falco.sh   (ver README, sección Falco)"
