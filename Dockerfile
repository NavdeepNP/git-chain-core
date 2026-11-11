# Git-Chain Immutable Container Target
FROM python:3.11-slim-bookworm

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as non-privileged user (SLSA Level 4 principle of least privilege)
USER 1001

CMD ["python", "git_chain.py"]
