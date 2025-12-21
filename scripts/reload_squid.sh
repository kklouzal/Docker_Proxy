#!/bin/sh

# Reload the Squid proxy configuration
squid -k reconfigure

# Check if the reload was successful
if [ $? -eq 0 ]; then
    echo "Squid configuration reloaded successfully."
else
    echo "Failed to reload Squid configuration."
fi