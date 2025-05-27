# Wordlist Collection

## Overview
This directory contains curated wordlists for different scanning scenarios.

## Wordlist Descriptions

### common.txt (Recommended for beginners)
- **Size**: ~500 entries
- **Purpose**: Most common directories and files
- **Usage**: Quick scans, initial reconnaissance
- **Examples**: admin, login, test, backup, config

### big.txt (Comprehensive scanning)
- **Size**: ~10,000+ entries
- **Purpose**: Exhaustive directory discovery
- **Usage**: Thorough security assessments
- **Warning**: May take significant time

### api.txt (API Discovery)
- **Size**: ~200 entries
- **Purpose**: API endpoints and versions
- **Examples**: api/v1, rest, graphql, swagger

### Technology-Specific Wordlists

#### wordpress.txt
- WordPress themes, plugins, admin areas
- wp-admin, wp-content, wp-includes

#### drupal.txt  
- Drupal-specific paths and modules
- sites/default, modules, themes

## Creating Custom Wordlists

1. One entry per line
2. No leading/trailing spaces
3. Use forward slashes for subdirectories
4. Include file extensions when relevant

Example:
