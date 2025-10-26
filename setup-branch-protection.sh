#!/bin/bash

# Set up branch protection rules for main branch
echo "Setting up branch protection for main branch..."

gh api repos/:owner/:repo/branches/main/protection \
  --method PUT \
  --header "Accept: application/vnd.github.v3+json" \
  --field required_status_checks='{
    "strict": true,
    "contexts": [
      "🛡️ Comprehensive Security Pipeline (security-gatekeeper)",
      "🔍 Semgrep Security Scan (semgrep)",
      "🛡️ Trivy Security Scan (trivy-fs-scan)",
      "🐷 TruffleHog Secret Detection (trufflehog-scan)"
    ]
  }' \
  --field enforce_admins='true' \
  --field required_pull_request_reviews='{
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true
  }' \
  --field restrictions='null'

echo "Branch protection rules configured!"