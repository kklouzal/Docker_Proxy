# SSL Configuration for Squid Proxy

This directory contains the necessary files and scripts to manage SSL certificates for the Squid proxy server. The following outlines the key components:

## Directory Structure

- **certs/**: This directory is intended to store the generated SSL certificates. It is currently empty and will be populated when certificates are created.
- **db/**: This directory is used to maintain the database for SSL certificates. It is also currently empty and will be populated as needed.

## Generating Self-Signed Certificates

To enable HTTPS caching capabilities, self-signed certificates must be generated. This can be done through the Flask web interface, which will provide an option to create and download the certificates.

## Usage

1. Access the Flask web application.
2. Navigate to the SSL configuration section.
3. Follow the prompts to generate a self-signed certificate.
4. Download the generated certificate for installation on client devices.

## Important Notes

- Ensure that the generated certificates are properly installed on client devices to avoid security warnings.
- Regularly check and manage the certificates to maintain secure connections through the Squid proxy.

For further details on the configuration and management of Squid, refer to the main documentation in the project root.