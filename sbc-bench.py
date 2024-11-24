import argparse
import glob
import hashlib
import os
import platform
import re
import statistics
import subprocess
import sys


REPOS = {
    "tinymembench": "https://github.com/nuumio/tinymembench",
    "cpuminer-multi": "https://github.com/tpruvot/cpuminer-multi",
}

PACKAGES = {
    "7zip": "7zip",
    "tinymembench": "make gcc",
    "cpuminer-multi": "automake make libssl-dev libcurl4-openssl-dev g++ zlib1g-dev",
}


def check_root():
    """Ensure the script is run as root."""
    if os.geteuid() != 0:
        sys.exit("This script must be run as root.")


def generate_system_id():
    """Generate a reproducible system-unique ID."""
    uname_info = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
    return hashlib.md5(uname_info.encode()).hexdigest()[:8]


def log_message(message, log_file):
    """Log a message to the console and a log file."""
    print(message)
    with open(log_file, "a") as f:
        f.write(message + "\n")


def run_command(command, cwd=None, log_file=None, timeout=0):
    """Run a shell command and return its output."""
    try:
        if timeout:
            command = f"timeout {timeout} {command}"
        if log_file:
            with open(log_file, "w") as fp:
                subprocess.run(
                    command,
                    shell=True,
                    check=True,
                    text=True,
                    cwd=cwd,
                    stdout=fp,
                    stderr=subprocess.STDOUT,
                )
        else:
            result = subprocess.run(
                command, shell=True, check=True, capture_output=True, text=True, cwd=cwd
            )
            return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        if not timeout:
            if log_file:
                os.remove(log_file)
            print(f"Failed to execute '{command}'.")
            sys.exit(1)

    return open(log_file).read()


def install_packages(packages):
    """Install required packages."""
    print("Installing packages...")
    if run_command(f"apt update && apt install -y {packages}"):
        print("Packages installed successfully.\n")
    else:
        print("Failed to install packages.")
        sys.exit(1)


def clone_repo(repo_name):
    """Clone a repository if not already present."""
    repo_url = REPOS[repo_name]
    repo_dir = repo_name
    if not os.path.exists(repo_dir):
        print(f"Cloning {repo_name}...")
        run_command(f"git clone {repo_url}", os.getcwd())
        return True
    return False


def run_benchmark(benchmark_name, command, system_id, overwrite, cwd=None, timeout=0):
    """Run a benchmark and save its raw output to a separate log file."""
    log_file = f"{system_id}-{benchmark_name}.log"

    if not overwrite and os.path.exists(log_file):
        print(f"Reusing existing output for {benchmark_name}.")
        with open(log_file, "r") as f:
            return f.read()

    print(f"Running {benchmark_name}...")
    output = run_command(command, cwd, log_file, timeout)
    return output


def parse_7zip_output(output):
    """Extract compression and decompression speeds from 7zip output."""
    match = re.search(r"Tot:\s+\d+\s+\d+\s+(\d+)", output, re.MULTILINE)
    if match:
        return {"Rating (MIPS)": match.group(1)}
    return {}


def parse_openssl_output(output):
    """Extract AES-256-CBC performance metrics."""
    match = re.search(r"AES-256-CBC\s+(\d+\.\d+)", output, re.MULTILINE)
    if match:
        score = float(match.group(1))
        return {"AES-256-CBC Speed (MB/s)": round(score)}
    return {}


def parse_tinymembench_output(output):
    """Extract memory bandwidth metrics."""
    memcpy_match = re.search(r"libc memcpy copy\s+:\s+([\d.]+)", output)
    memset_match = re.search(r"libc memchr scan\s+:\s+([\d.]+)", output)

    memcpy_score = float(memcpy_match.group(1)) if memcpy_match else None
    memset_score = float(memset_match.group(1)) if memset_match else None

    if memcpy_match and memset_match:
        return {
            "libc memcpy copy (MB/s)": round(memcpy_score),
            "libc memchr scan (MB/s)": round(memset_score),
        }
    return {}


def parse_cpuminer_output(output):
    """Extract hash rate from cpuminer output."""
    matches = re.findall(r"Total: (\d+\.\d+)\s+kH/s", output, re.MULTILINE)
    if matches:
        scores = list(map(float, matches))
        score = statistics.median(scores)
        return {"Hashrate (kH/s)": round(score)}
    return {}


def run_7zip_benchmark(system_id, overwrite):
    """Run the 7zip benchmark."""
    multi_output = run_benchmark("7zip-multi", "7zz b", system_id, overwrite)
    single_output = run_benchmark("7zip-single", "7zz b -mmt=1", system_id, overwrite)
    return {
        f"Multi-threaded": parse_7zip_output(multi_output),
        f"Single-threaded": parse_7zip_output(single_output),
    }


def run_openssl_benchmark(system_id, overwrite):
    """Run the OpenSSL AES-256-CBC benchmark."""
    output = run_benchmark(
        "openssl", "openssl speed -elapsed -evp aes-256-cbc", system_id, overwrite
    )
    return parse_openssl_output(output)


def run_memory_benchmark(system_id, overwrite):
    """Run the memory benchmark using tinymembench."""
    if clone_repo("tinymembench"):
        print("Building tinymembench")
        run_command("make", cwd="tinymembench")
    output = run_benchmark(
        "tinymembench",
        "./tinymembench/tinymembench -b 2 -B 3 -l 3 -c 1000000",
        system_id,
        overwrite,
    )
    return parse_tinymembench_output(output)


def run_cpuminer_benchmark(system_id, overwrite):
    """Run the cpuminer stress test."""
    if clone_repo("cpuminer-multi"):
        print("Building cpuminer-multi")
        run_command("./build.sh", cwd="cpuminer-multi")
    output = run_benchmark(
        "cpuminer",
        "./cpuminer --benchmark --cpu-priority 2",
        system_id,
        overwrite,
        "cpuminer-multi",
        60,
    )
    return parse_cpuminer_output(output)


def get_cpu_name():
    """Retrieve the CPU name."""
    try:
        with open("/proc/cpuinfo", "r") as cpuinfo:
            content = cpuinfo.read()
            match = re.search(r"model name\s*:\s*(.+)", content)
            if match:
                return match.group(1).strip()
    except FileNotFoundError:
        return platform.processor() or "Unknown CPU"


def get_cpu_frequency():
    """Determine the highest CPU frequency."""
    freq_files = glob.glob("/sys/devices/system/cpu/cpufreq/policy?/cpuinfo_max_freq")

    if not freq_files:
        return "N/A"

    freqs = sorted(int(open(file).read().strip()) for file in freq_files)
    highest_clock = max(freqs)
    mhz = f"{highest_clock // 1000} MHz"
    return mhz


def get_kernel_version():
    """Retrieve the short kernel version."""
    kernel_version = os.uname().release
    match = re.search(r"(\d\.\d+\.\d+)", os.uname().release)
    if match:
        return match.group(0)
    else:
        return ".".join(kernel_version.split(".")[:2])


def get_distro_info():
    """Retrieve distribution info."""
    try:
        operating_system = (
            subprocess.check_output(["lsb_release", "-d"], text=True)
            .split(":", 1)[1]
            .strip()
        )
    except FileNotFoundError:
        operating_system = "Unknown OS"

    # Kernel architecture
    arch = os.uname().machine
    distro_info = f"{operating_system} {arch}"
    return distro_info


def print_system_info(system_id):
    """Print system information."""
    print(f"System ID     : {system_id}")
    print(f"CPU name      : {get_cpu_name()}")
    print(f"CPU frequency : {get_cpu_frequency()}")
    print(f"Kernel version: {get_kernel_version()}")
    print(f"Distribution  : {get_distro_info()}")


def print_summary(results):
    """Print a summary of benchmark results."""
    scores = list()
    for benchmark, metrics in results.items():
        print(f"\n{benchmark}:")
        for metric, value in metrics.items():
            if type(value) == dict:
                unit = list(value.keys())[0]
                value = list(value.values())[0]
                print(f"  {metric} {unit}: {value}")
            else:
                print(f"  {metric}: {value}")
            scores.append(value)
    return scores


def print_score(args, results):
    """Print system information and scores in sbc-bench format."""
    scores = list()
    for _, metrics in results.items():
        for _, value in metrics.items():
            if type(value) == dict:
                value = list(value.values())[0]
            scores.append(value)

    cpu_name = get_cpu_name()
    mhz = get_cpu_frequency()
    short_kernel_version = get_kernel_version()
    distro_info = get_distro_info()
    summary = f"\n| {cpu_name} | {mhz} | {short_kernel_version} | {distro_info} | {' | '.join(map(str, scores))} | "

    # Complete output in case cpuminer was not executed
    if not args.c:
        summary += "0 |"

    print(summary)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--install", action="store_true", help="Install required dependencies"
    )
    parser.add_argument(
        "--overwrite", action="store_true", help="Overwrite existing results"
    )
    parser.add_argument("-c", action="store_true", help="Run the cpuminer benchmark")
    args = parser.parse_args()

    if args.install:
        check_root()
        packages = " ".join([PACKAGES["7zip"], PACKAGES["tinymembench"]])
        if args.c:
            packages += " " + PACKAGES["cpuminer-multi"]
        install_packages(packages)

    system_id = generate_system_id()

    print_system_info(system_id)

    print("\nStarting benchmarks...")
    results = {}

    results["7zip"] = run_7zip_benchmark(system_id, args.overwrite)
    results["OpenSSL"] = run_openssl_benchmark(system_id, args.overwrite)
    results["Memory"] = run_memory_benchmark(system_id, args.overwrite)

    if args.c:
        results["CPUMiner"] = run_cpuminer_benchmark(system_id, args.overwrite)

    print_summary(results)
    print_score(args, results)


if __name__ == "__main__":
    main()
