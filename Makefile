# campus-device-bypass —— wxdet-gate 构建入口
GO   ?= go
BIN  := wxdet-gate

.PHONY: all check fmt vet test build arm64 clean

all: check build

check: fmt vet test

# gofmt 只检查不改写：有未格式化文件即失败
fmt:
	@out="$$(gofmt -l gate)"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	cd gate && $(GO) vet ./...

test:
	cd gate && $(GO) test ./...

build:
	cd gate && $(GO) build -o $(BIN) .

# 常见路由器平台（arm64），静态编译、去符号
arm64:
	cd gate && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
		$(GO) build -trimpath -ldflags "-s -w" -o $(BIN)-arm64 .

clean:
	rm -f gate/$(BIN) gate/$(BIN)-arm64
