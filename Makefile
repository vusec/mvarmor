SUBDIRS = libmultivar dune_sandbox ptrace

all:
	@echo "Make sure you've either run 'make deps' or modified config.mk"
	for dir in $(SUBDIRS); do \
		make -C $$dir; \
	done

deps: deps/shalloc deps/dune deps/libumem
deps/shalloc:
	git clone https://github.com/vusec/shalloc deps/shalloc
	make -C deps/shalloc
deps/dune:
	git clone https://github.com/vusec/dune deps/dune
	make -C deps/dune
deps/libumem:
	git clone https://github.com/vusec/libumem-mvx deps/libumem
	cd deps/libumem ; ./autogen.sh ; ./configure --prefix=`pwd`/install
	make -C deps/libumem install


clean:
	for dir in $(SUBDIRS); do \
		make -C $$dir clean; \
	done

distclean: clean
	rm -rf deps/

.PHONY: all deps clean
