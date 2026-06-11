.PHONY: benchmark benchmark-local seqfw-release

seqfw-release:
	cargo build --release -p seqfw-cli

# Local subset: block rate + false positives + overhead vs the seqfw binary.
# Deterministic, no Docker, no vulnerable tools required.
benchmark-local: seqfw-release
	python3 benchmark/gen_corpus.py
	python3 benchmark/run_block_rate.py

# Full benchmark including the ASAN "harm prevented" run (needs a Docker host).
benchmark: seqfw-release
	python3 benchmark/gen_corpus.py
	docker build -f benchmark/Dockerfile -t seqfw-benchmark .
	docker run --rm seqfw-benchmark
