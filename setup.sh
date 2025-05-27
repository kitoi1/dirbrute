#!/bin/bash
# setup.sh - Automated DirBruter setup

set -e  # Exit on any error

echo "🚀 Setting up DirBruter..."

# Create directory structure with verbose output
echo "📁 Creating directories..."
for dir in wordlists/technology config examples tests/fixtures output logs docs; do
  if [ ! -d "$dir" ]; then
    mkdir -p "$dir" && echo "✔ Created directory: $dir"
  else
    echo "ℹ Directory already exists: $dir"
  fi
done

# Create Python package files if they don't exist
for pkg in config tests; do
  init_file="$pkg/__init__.py"
  if [ ! -f "$init_file" ]; then
    touch "$init_file" && echo "✔ Created Python package file: $init_file"
  else
    echo "ℹ Python package file already exists: $init_file"
  fi
done

echo "✅ Setup complete! You're ready to start development."
