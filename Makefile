UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	LIB_EXT := dylib
else ifeq ($(OS),Windows_NT)
	LIB_EXT := dll
else
	LIB_EXT := so
endif

LIB_NAME := libproton.$(LIB_EXT)

.PHONY: libproton libproton-static clean

libproton:
	CGO_ENABLED=1 go build -buildmode=c-shared -o $(LIB_NAME) ./cmd/export/

libproton-static:
	CGO_ENABLED=1 go build -buildmode=c-archive -o libproton.a ./cmd/export/

clean:
	rm -f libproton.so libproton.dylib libproton.dll libproton.a libproton.h
