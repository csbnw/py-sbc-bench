# py-sbc-bench

A simplified Python implementation of the [sbc-bench](https://github.com/ThomasKaiser/sbc-bench/tree/master/results) script.

This script reproduces the functionality of `./sbc-bench.sh -c`, focusing solely on obtaining benchmark results without the additional features like frequency and temperature monitoring.

Like `sbc-bench`, this script assumes that you are using a recent Debian or Ubuntu distribution.

## Features

- Runs a set of CPU benchmarks:
  - **7-zip**: Measures single-threaded and multi-threaded compression performance.
  - **OpenSSL**: Measures cryptographic performance (AES and SHA operations).
  - **tinymembench**: Measures memory throughput and latency.
  - **cpuminer (optional)**: Performs CPU mining performance (NEON/SSE/AVX optimizations).
- Stores benchmark results in separate log files for easy analysis.
- Simple usage for quick and reliable benchmarking.

## Usage

Run the script with the desired options using the following command:

```bash
python3 sbc-bench.py [OPTIONS]
```

It has the following command-line arguments:

- `--install`: Automatically install some required dependencies (requires root).
- `--overwrite`: Re-run benchmarks and overwrite existing results.
- `-c`: Include the cpuminer benchmark (disabled by default).
