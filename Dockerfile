FROM debian:12
RUN apt-get update
RUN apt-get install -y git python3
RUN git clone https://github.com/csbnw/py-sbc-bench
WORKDIR /host
CMD python3 /py-sbc-bench/sbc-bench.py --install -c
