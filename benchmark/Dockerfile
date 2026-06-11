# seqfw security benchmark — harm-prevented stage.
#
# Builds pinned, unmodified htslib 1.10.2 + bcftools 1.10.2 under AddressSanitizer
# + UBSan (no FUZZING_BUILD_MODE, no weakened victim), and a release seqfw, then
# runs run_harm_prevented.py. The pinned 1.10.2 window is the CVE-2020-36403
# vcf_parse_format out-of-bounds write.

# --- stage 1: build the seqfw binary (linux) -------------------------------
FROM rust:1-bookworm AS seqfw-build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p seqfw-cli

# --- stage 2: ASAN-built htslib/bcftools + the runner ----------------------
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential clang autoconf automake \
        zlib1g-dev libbz2-dev liblzma-dev libcurl4-openssl-dev libssl-dev \
        curl ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

ENV CC=clang
ENV SAN="-fsanitize=address,undefined -fno-sanitize-recover=all -g -O1"
# Detect real bugs; do not let the sanitizer recover and mask a crash.
ENV ASAN_OPTIONS=halt_on_error=1:abort_on_error=1:detect_leaks=0

WORKDIR /build
# Pinned htslib 1.10.2 (CVE-2020-36403 window).
RUN curl -fsSL -o htslib.tar.bz2 \
      https://github.com/samtools/htslib/releases/download/1.10.2/htslib-1.10.2.tar.bz2 \
    && tar xjf htslib.tar.bz2 && cd htslib-1.10.2 \
    && ./configure CC=clang CFLAGS="$SAN" LDFLAGS="$SAN" --disable-libcurl \
    && make -j"$(nproc)" && make install && ldconfig
# Pinned bcftools 1.10.2, linked against the ASAN htslib.
RUN curl -fsSL -o bcftools.tar.bz2 \
      https://github.com/samtools/bcftools/releases/download/1.10.2/bcftools-1.10.2.tar.bz2 \
    && tar xjf bcftools.tar.bz2 && cd bcftools-1.10.2 \
    && ./configure CC=clang CFLAGS="$SAN" LDFLAGS="$SAN" --with-htslib=/build/htslib-1.10.2 \
    && make -j"$(nproc)" && make install

WORKDIR /seqfw
COPY benchmark ./benchmark
COPY corpus ./corpus
COPY --from=seqfw-build /src/target/release/seqfw /usr/local/bin/seqfw
ENV SEQFW_BIN=/usr/local/bin/seqfw

# Regenerate the corpus inside the image, then run both halves.
CMD ["sh", "-c", "python3 benchmark/gen_corpus.py && python3 benchmark/run_block_rate.py; python3 benchmark/run_harm_prevented.py"]
