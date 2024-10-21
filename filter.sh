#!/bin/bash

# Ask the user for the website URL or domain
read -p "Enter the website URL or domain: " website_input

# Normalize the input: Add "https://" if the input is just a domain without protocol
if [[ ! $website_input =~ ^https?:// ]]; then
    website_url="https://$website_input"
else
    website_url="$website_input"
fi

# Inform the user of the normalized URL being used
echo "Normalized URL being used: $website_url"


# Step 1: Run katana with passive sources and save output to a unified file (output/output.txt)
echo "Running katana with passive sources (waybackarchive, commoncrawl, alienvault)..."
echo "$website_url" | katana -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | uro > "output.txt"

# Step 2: Run katana actively with depth 5 and append results to output/output.txt
echo "Running katana actively with depth 5..."
katana -u "$website_url" -d 5 -f qurl | uro | anew "output.txt"


# Step 3: Filter output/output.txt for different vulnerabilities

# SQLi
echo "Filtering URLs for potential SQLi endpoints..."
cat "output.txt" | gf sqli | sed 's/=.*/=/' | sort -u > "urls.txt"

# Remove the intermediate file output/output.txt
rm "output.txt"

# Notify the user that all tasks are complete
echo "Filtered URLs have been saved to the respective output files in the 'output' directory:"
echo "  - SQLi: urls.txt"
