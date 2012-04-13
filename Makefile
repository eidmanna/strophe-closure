SHELL=/bin/bash

SRC_DIR = src
DOC_DIR = doc
PLUGIN_DIR = plugins
NDPROJ_DIR = ndproj

BASE_FILES = $(SRC_DIR)/core.js \
	     $(SRC_DIR)/exports.js

STROPHE_MIN = strophe.min.js

CALCDEPS = python $(HOME)/src/closure-library/closure/bin/calcdeps.py \
	          --path=$(HOME)/src/closure-library \
		  --output_mode=compiled \
		  --compiler_jar=$(HOME)/src/closure-compiler/build/compiler.jar \
		  --compiler_flags="--compilation_level=ADVANCED_OPTIMIZATIONS" \
		  --compiler_flags="--warning_level=VERBOSE" \
		  --compiler_flags="--define='goog.DEBUG=false'" \
		  --compiler_flags="--output_wrapper='(function(){%output%})();'" \
		  --output_file=$@

$(STROPHE_MIN): $(BASE_FILES)
	$(CALCDEPS) $(foreach file,$(BASE_FILES),--input=$(file))

PLUGIN_FILES = $(shell ls $(PLUGIN_DIR)/strophe.*.js | grep -v min)
PLUGIN_FILES_MIN = $(PLUGIN_FILES:.js=.min.js)

DIST_FILES = LICENSE.txt README.txt contrib examples plugins tests doc \
		$(STROPHE) $(STROPHE_MIN)

VERSION = $(shell if [ -f version.txt ]; then cat version.txt; else VERSION=`git rev-list HEAD -n1`; echo $${VERSION:0:7}; fi)

all: min

min: $(STROPHE_MIN) $(PLUGIN_FILES_MIN)

doc:
	@@echo "Building Strophe documentation..."
	@@if [ ! -d $(NDPROJ_DIR) ]; then mkdir $(NDPROJ_DIR); fi
	@@if [ ! -d $(DOC_DIR) ]; then mkdir $(DOC_DIR); fi
	@@NaturalDocs -q -i $(SRC_DIR) -i $(PLUGINS_DIR) -o html $(DOC_DIR) -p $(NDPROJ_DIR)
	@@echo "Documentation built."
	@@echo

release: min doc
	@@echo "Creating release packages..."
	@@mkdir strophejs-$(VERSION)
	@@cp -R $(DIST_FILES) strophejs-$(VERSION)
	@@tar czf strophejs-$(VERSION).tar.gz strophejs-$(VERSION)
	@@zip -qr strophejs-$(VERSION).zip strophejs-$(VERSION)
	@@rm -rf strophejs-$(VERSION)
	@@echo "Release created."
	@@echo

clean:
	@@echo "Cleaning" $(STROPHE) "..."
	@@rm -f $(STROPHE)
	@@echo $(STROPHE) "cleaned."
	@@echo "Cleaning" $(STROPHE_MIN) "..."
	@@rm -f $(STROPHE_MIN)
	@@echo $(STROPHE_MIN) "cleaned."
	@@echo "Cleaning minified plugins..."
	@@rm -f $(PLUGIN_FILES_MIN)
	@@echo "Minified plugins cleaned."
	@@echo "Cleaning documentation..."
	@@rm -rf $(NDPROJ_DIR) $(DOC_DIR)
	@@echo "Documentation cleaned."
	@@echo

.PHONY: all min doc release clean
