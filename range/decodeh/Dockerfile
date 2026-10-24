# Split-rig decoder harness: ARG selects vulnerable vs patched lineage.
# vuln:  --build-arg BROTLI_TAG=v1.2.0 --build-arg SAN=1   -> decodeh-asan
# plain: --build-arg BROTLI_TAG=v1.2.0 --build-arg SAN=0   -> decodeh (exploitation oracle)
# ctrl:  --build-arg BROTLI_TAG=v1.2.1 --build-arg SAN=1   -> patched negative control
FROM ubuntu:24.04
ARG BROTLI_TAG=v1.2.0
ARG SAN=1
# libasan8/libubsan1: sanitizer RUNTIMES - gcc recommends-level deps that
# --no-install-recommends skips (ASan link silently failed without them; banked).
RUN apt-get update -q && apt-get install -y -q --no-install-recommends \
    git cmake make gcc gdb ca-certificates libasan8 libubsan1 \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch ${BROTLI_TAG} https://github.com/google/brotli.git /brotli
WORKDIR /brotli
RUN cmake -B build -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_FLAGS="-O1 -g $( [ "$SAN" = "1" ] && echo '-fsanitize=address,undefined -fno-omit-frame-pointer' )" \
      -DBUILD_SHARED_LIBS=OFF -DBROTLI_DISABLE_TESTS=ON \
 && cmake --build build --target brotlidec -j4
COPY harness.c /harness.c
RUN gcc -O1 -g -I/brotli/c/include $( [ "$SAN" = "1" ] && echo '-fsanitize=address,undefined -fno-omit-frame-pointer' ) \
      /harness.c /brotli/build/libbrotlidec.a -o /decode
# usage: /decode file.br           one-shot BrotliDecoderDecompress
#        /decode --stream file.br  streaming, fresh output chunk (partial-input paths)
#        /decode --ring file.br    streaming, REUSED fixed output buffer (server-reuse model)
CMD ["/decode"]
