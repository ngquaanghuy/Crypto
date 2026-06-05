# =============================================================================
# Dockerfile — Crypto v1.6.1 (Python Script Protector)
# Multi-stage build: builder (full toolchain) → runtime (minimal deps)
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1 — Builder: compile Crypto + run unit tests
# ---------------------------------------------------------------------------
FROM archlinux:latest AS builder

LABEL stage=builder

# Install ALL build & test dependencies in one layer
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm \
        gcc \
        cmake \
        make \
        pkg-config \
        openssl \
        zlib \
        bzip2 \
        xz \
        brotli \
        python \
        python-pip \
    && pacman -Scc --noconfirm

# Optional Python packages for obfuscation / VM tests
RUN pip install --no-cache-dir lz4 snappy brotli blosc 2>/dev/null || true

WORKDIR /src

# Copy entire project (use .dockerignore to trim)
COPY . .

# Build the binary + tests in /build (not in /src — keeps source clean)
RUN cmake -S /src -B /build \
        -DCMAKE_BUILD_TYPE=MinSizeRel \
        -DCRYPTO_BUILD_TESTS=ON \
    && cmake --build /build -j$(nproc) \
    && strip /build/crypto /build/test_crypto

# ---------------------------------------------------------------------------
# Stage 2 — Runtime: only the binary + shared libs + Python
# ---------------------------------------------------------------------------
FROM archlinux:latest AS runtime

LABEL vendor="Crypto Project" \
      version="1.6.1" \
      description="CRYPTO — Python Script Protector CLI"

# Full dev environment: build tools + shared libs + Python
RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm \
        gcc \
        cmake \
        make \
        pkg-config \
        openssl \
        zlib \
        bzip2 \
        xz \
        brotli \
        python \
        python-pip \
    && pacman -Scc --noconfirm

# Optional Python packages needed when a protected stub uses an
# external compression algorithm at runtime (lz4, snappy, brotli, etc.)
# If missing, the stub will report a clear error — these are best-effort.
RUN pip install --no-cache-dir lz4 snappy brotli blosc 2>/dev/null || true

# Copy only the production binary from builder
COPY --from=builder /build/crypto /usr/local/bin/crypto

WORKDIR /data

CMD ["/bin/bash"]