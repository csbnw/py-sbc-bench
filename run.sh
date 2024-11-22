#!/bin/bash
docker build --tag py-sbc-bench .
docker run -t --rm -v $(pwd):/host py-sbc-bench
