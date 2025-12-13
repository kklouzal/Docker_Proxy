# This file contains documentation related to custom error pages for Squid. 

Custom error pages can be configured in Squid to provide a better user experience when errors occur. This directory is intended to hold the HTML files for these custom error pages.

To use custom error pages, you need to modify the Squid configuration file (squid.conf) to point to these pages. Here are some common error pages you might want to customize:

- **ERR_ACCESS_DENIED**: This error occurs when access to a requested resource is denied.
- **ERR_CONNECT_FAIL**: This error occurs when Squid fails to connect to the requested server.
- **ERR_DNS_FAIL**: This error occurs when DNS resolution fails for a requested URL.

To create a custom error page, follow these steps:

1. Create an HTML file in this directory for the specific error you want to customize.
2. Update the Squid configuration to reference your custom error page. For example:
   ```
   error_directory /path/to/squid/error_pages
   ```
3. Reload the Squid configuration to apply the changes.

Make sure to test your custom error pages to ensure they display correctly and provide helpful information to users.