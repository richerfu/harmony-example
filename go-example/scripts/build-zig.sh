#!/bin/bash

CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 CC="zig cc -target aarch64-macos" CXX="zig c++ -target aarch64-macos" go build -o ../go-shared/libadd.dylib -buildmode=c-shared ../go-shared/add.go