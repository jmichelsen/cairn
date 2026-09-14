# Cached CI image for cairn's test/lint stage. The heavy apt (nodejs, for `node --check` in check_js.py)
# and pip (fastapi/uvicorn/pytest) layers sit BEFORE the source COPY, so with BuildKit inline cache +
# --cache-from they are reused across pipeline runs (seconds instead of ~2-3 min). The final RUN executes
# the checks: a source change re-runs them, but the deps stay cached, and a failed `docker build` == a
# failed test stage. Used by both cairn/.gitlab-ci.yml and cairn-deploy/.gitlab-ci.yml.
FROM python:3.12-slim
ENV DEBIAN_FRONTEND=noninteractive PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1

RUN apt-get update -qq \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir pyyaml "fastapi>=0.110" "uvicorn[standard]>=0.29" pytest

WORKDIR /src
# only the test-relevant tree, so unrelated changes (README, etc.) don't bust the test layer
COPY phase1 /src/phase1
COPY tools  /src/tools
COPY tests  /src/tests
COPY agent.py VERSION /src/

RUN python3 -m py_compile phase1/*.py agent.py \
 && python3 tools/check_js.py \
 && python3 -m pytest -q
