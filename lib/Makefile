OUT := my
FUNC := Test
VERSION := $(shell git describe --always --long)

all: run

build:
	go build -i -v -o ${OUT}.dll -buildmode=c-shared -ldflags "-w -s -X main.version=${VERSION}"

run: build
	rundll32.exe ${OUT}.dll ${FUNC}

clean:
	-@rm ${OUT}.dll ${OUT}.h #${OUT}-*

.PHONY: build run clean
