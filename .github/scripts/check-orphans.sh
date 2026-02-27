#!/bin/bash
set -e

echo "🔍 Checking for orphaned markdown files..."

# Find all markdown files
ALL_MD_FILES=$(find . -name "*.md" -not -path "*/node_modules/*" -not -path "*/.git/*" | sed 's|^\./||' | sort)

# Find all markdown links in files
LINKED_FILES=$(grep -rh --include="*.md" -oP '\[.*?\]\(\K[^)]+' . | grep "\.md" | sed 's/#.*//' | sed 's|^\./||' | sort | uniq)

ORPHANS=0
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

echo ""
echo "📊 Analysis Results:"
echo ""

# Check each markdown file
for file in $ALL_MD_FILES; do
  # Skip README files and the main cheatsheet as they're entry points
  if [[ "$file" == "README.md" ]] || [[ "$file" == "KCSA_CHEATSHEET.md" ]]; then
    continue
  fi

  # Check if file is linked anywhere
  if ! echo "$LINKED_FILES" | grep -q "$file"; then
    echo -e "${YELLOW}⚠️  Orphaned file: $file${NC}"
    ORPHANS=$((ORPHANS + 1))
  fi
done

echo ""
echo "========================================"
if [ $ORPHANS -eq 0 ]; then
  echo -e "${GREEN}✅ No orphaned files found!${NC}"
else
  echo -e "${YELLOW}⚠️  Found $ORPHANS orphaned file(s)${NC}"
  echo -e "${YELLOW}   Consider linking them or removing if unused${NC}"
fi

# Non-blocking - always exit 0
exit 0
