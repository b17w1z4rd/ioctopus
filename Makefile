PYTHON ?= python3

# ioctopus is a single stdlib-only script; "build" just makes it executable.
build:
	chmod +x ioctopus.py

run:
	$(PYTHON) ioctopus.py sample-report.txt

# Extract from the sample report and sanity-check the key behaviours.
test:
	@echo "### table ###"
	@$(PYTHON) ioctopus.py sample-report.txt --no-color
	@echo
	@echo "### checks ###"
	@$(PYTHON) ioctopus.py sample-report.txt --json | $(PYTHON) -c 'import sys,json; d=json.load(sys.stdin); \
	assert any(i["value"]=="45.138.12.99" for i in d.get("ipv4",[])), "refang ipv4 failed"; \
	assert any("DGA" in "".join(i["tags"]) for i in d.get("domain",[])), "DGA scoring failed"; \
	assert any(i["value"]=="drift-invoices.com" for i in d.get("domain",[])), "domain extract failed"; \
	assert any("private" in i["tags"] for i in d.get("ipv4",[])), "private-ip tag failed"; \
	assert d.get("cve"), "cve failed"; assert d.get("sha256"), "sha256 failed"; \
	print("ok: refang, DGA entropy, private-ip tagging, CVE + hashes all verified")'
	@echo
	@echo "### STIX 2.1 bundle validates as JSON with indicator SDOs ###"
	@$(PYTHON) ioctopus.py sample-report.txt --stix | $(PYTHON) -c 'import sys,json; b=json.load(sys.stdin); \
	assert b["type"]=="bundle" and b["objects"][0]["type"]=="indicator"; \
	print("ok: valid STIX bundle with", len(b["objects"]), "indicators")'

clean:
	rm -f *.pyc
	rm -rf __pycache__

.PHONY: build run test clean
