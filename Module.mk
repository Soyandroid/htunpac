include kernal32/Module.mk
include pedumper/Module.mk
include util/Module.mk

#
# Distribution build rules
#

zipdir          := $(BUILDDIR)/zip

$(zipdir)/:
	$(V)mkdir -p $@

$(BUILDDIR)/htunpac.zip: \
		build/bin/indep-32/kernal32.dll \
		build/bin/indep-32/pedumper.exe \

	$(V)echo ... $@
	$(V)zip -j $@ $^

all: $(BUILDDIR)/htunpac.zip
