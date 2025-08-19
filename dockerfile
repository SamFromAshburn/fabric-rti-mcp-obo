FROM mcr.microsoft.com/azure-cli:azurelinux3.0
WORKDIR /app

# Install system dependencies
RUN tdnf install -y git tar
RUN tdnf clean all

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

# Set up Python environment
RUN uv venv
RUN uv python install 3.11

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN uv pip install -r requirements.txt

# Copy the rest of the application
COPY . /app
RUN chmod +x fabric_rti_mcp/server.py

# Install the application itself
RUN uv pip install .

ENV KUSTO_SERVICE_URI=
ENV KUSTO_SERVICE_DEFAULT_DB=

# Tenant ID for Entra you are connecting to
ENV TENANT_ID=

# Enable On-Behalf-Of (OBO) flow
ENV USE_OBO=false
# OBO flow required. The App Registration ID of the middle-tier service. That is this service, NOT the user.
ENV CLIENT_ID=
 # OBO flow required. Name of the cert in keyvault
ENV AZURE_CLIENT_CERTIFICATE_NAME=
 # OBO flow required. Keyvault endpoint
ENV KEYVAULT_URL=

EXPOSE 80
CMD ["uv", "run", "-m", "fabric_rti_mcp.server"]