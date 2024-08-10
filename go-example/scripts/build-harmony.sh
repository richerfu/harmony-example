#!/bin/bash

CGO_ENABLED=1 GOOS=linux GOARCH=arm64 CC="zig cc -target aarch64-linux-ohos" CXX="zig c++ -target aarch64-linux-ohos" go build -o ../go-shared/libadd.so -buildmode=c-shared ../go-shared/add.go