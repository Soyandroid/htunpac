include kernal32/Module.mk
include pre-dump/Module.mk
include pedumper/Module.mk
include util/Module.mk

#
# Distribution build rules
#

zipdir          := $(BUILDDIR)/zip

$(zipdir)/:
	$(V)mkdir -p $@

$(BUILDDIR)/htunpac.zip: \
		dist/HtsysmNT.sys \
		dist/unpac.bat \
		build/bin/indep-32/kernal32.dll \
		build/bin/indep-32/pedumper.exe \
		build/bin/indep-32/pre-dump.exe \

	$(V)echo ... $@
	$(V)zip -j $@ $^

all: $(BUILDDIR)/htunpac.zip
