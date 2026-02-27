#!/bin/bash
set -e

echo "🔍 Validating repository structure..."

ERRORS=0
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Check domain README files
echo "📁 Checking domain structure..."
DOMAIN_DIRS=(
  "domains/01-cluster-setup"
  "domains/02-cluster-hardening"
  "domains/03-system-hardening"
  "domains/04-minimize-vulnerabilities"
  "domains/05-supply-chain-security"
  "domains/06-monitoring-logging"
)

for dir in "${DOMAIN_DIRS[@]}"; do
  if [ ! -f "$dir/README.md" ]; then
    echo -e "${RED}❌ Missing README.md in $dir${NC}"
    ERRORS=$((ERRORS + 1))
  else
    echo -e "${GREEN}✓${NC} $dir/README.md exists"
  fi
done

# Check lab directories
echo ""
echo "🧪 Checking lab structure..."
LAB_DIRS=(
  "labs/01-cluster-setup"
  "labs/02-cluster-hardening"
  "labs/03-system-hardening"
  "labs/04-minimize-vulnerabilities"
  "labs/05-supply-chain-security"
  "labs/06-monitoring-logging"
)

for dir in "${LAB_DIRS[@]}"; do
  if [ ! -d "$dir" ]; then
    echo -e "${RED}❌ Missing lab directory: $dir${NC}"
    ERRORS=$((ERRORS + 1))
  else
    LAB_COUNT=$(find "$dir" -name "lab-*.md" 2>/dev/null | wc -l | tr -d ' ')
    echo -e "${GREEN}✓${NC} $dir exists with $LAB_COUNT lab files"
  fi
done

# Check required root files
echo ""
echo "📄 Checking required root files..."
REQUIRED_FILES=(
  "README.md"
  "KCSA_CHEATSHEET.md"
)

for file in "${REQUIRED_FILES[@]}"; do
  if [ ! -f "$file" ]; then
    echo -e "${RED}❌ Missing required file: $file${NC}"
    ERRORS=$((ERRORS + 1))
  else
    echo -e "${GREEN}✓${NC} $file exists"
  fi
done

# Check mock questions directory
echo ""
echo "📝 Checking mock questions..."
if [ ! -d "mock-questions" ]; then
  echo -e "${RED}❌ Missing mock-questions directory${NC}"
  ERRORS=$((ERRORS + 1))
else
  MOCK_COUNT=$(find mock-questions -name "mock-exam-*.md" 2>/dev/null | wc -l | tr -d ' ')
  echo -e "${GREEN}✓${NC} mock-questions directory exists with $MOCK_COUNT exam files"
fi

# Check GitHub Actions workflow
echo ""
echo "🔧 Checking CI/CD configuration..."
if [ ! -f ".github/workflows/pr-validation.yml" ]; then
  echo -e "${RED}❌ Missing .github/workflows/pr-validation.yml${NC}"
  ERRORS=$((ERRORS + 1))
else
  echo -e "${GREEN}✓${NC} GitHub Actions workflow exists"
fi

# Final report
echo ""
echo "========================================"
if [ $ERRORS -eq 0 ]; then
  echo -e "${GREEN}✅ Structure validation passed!${NC}"
  exit 0
else
  echo -e "${RED}❌ Structure validation failed with $ERRORS error(s)${NC}"
  exit 1
fi
