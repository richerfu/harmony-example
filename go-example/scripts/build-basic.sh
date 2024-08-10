#!/bin/bash

CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o ../go-shared/libadd.dylib -buildmode=c-shared ../go-shared/add.go