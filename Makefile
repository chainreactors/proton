BINARY = found
TEMPLATES_DIR = templates
TEMPLATES_ARCHIVE = templates.tar.gz

.PHONY: build clean templates

templates: $(TEMPLATES_ARCHIVE)

$(TEMPLATES_ARCHIVE): $(shell find $(TEMPLATES_DIR) -name '*.yaml' -o -name '*.yml')
	tar czf $@ -C $(TEMPLATES_DIR) .

build: $(TEMPLATES_ARCHIVE)
	go build -o $(BINARY) .

clean:
	rm -f $(BINARY) $(TEMPLATES_ARCHIVE)
