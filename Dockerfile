# ==========================================
# 階段 1: 編譯構建 (Builder)
# 使用輕量 Alpine Linux 並安裝 C++20 編譯工具與 CMake
# ==========================================
FROM alpine:3.19 AS builder

RUN apk update && apk add --no-cache \
    build-base \
    cmake \
    git

WORKDIR /build

# 複製 CMake 與原始碼檔案
COPY CMakeLists.txt .
COPY include/ include/
COPY src/ src/
COPY config/ config/

# 執行標準 CMake 編譯
RUN mkdir -p build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    cmake --build . --config Release

# ==========================================
# 階段 2: 最小運行映像 (Runner)
# ==========================================
FROM alpine:3.19 AS runner

RUN apk update && apk add --no-cache \
    libstdc++ \
    libgcc \
    curl

WORKDIR /app

# 從 builder 複製產出物
COPY --from=builder /build/build/waf /app/waf
COPY --from=builder /build/config/ /app/config/

# 開放 WAF 監聽埠號 8080
EXPOSE 8080

# 預設啟動 WAF 主程式
ENTRYPOINT ["/app/waf"]
