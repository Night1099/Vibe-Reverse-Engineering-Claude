FROM python:3.11-slim

WORKDIR /workspace

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl git && rm -rf /var/lib/apt/lists/*

# Python deps — repo requirements + harness extras
COPY requirements.txt /workspace/requirements.txt
COPY harness/requirements-harness.txt /workspace/requirements-harness.txt
RUN pip install --no-cache-dir -r requirements.txt -r requirements-harness.txt

# Copy repo
COPY . /workspace/

# Verify install (non-blocking — Ghidra download is optional)
RUN python verify_install.py || true

EXPOSE 8080 4000

ENTRYPOINT ["python", "-m", "harness"]
CMD ["serve", "--port", "8080"]
