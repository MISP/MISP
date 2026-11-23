#!/bin/bash
# Test for issue #9596: Ensure feed headers are not leaked in API
# Usage: ./curl_test_feed_headers.sh <MISP_URL> <API_KEY>
MISP_URL="${1:-https://localhost}"
MISP_API_KEY="$2"

if [ -z "$MISP_API_KEY" ]; then
  echo "Usage: $0 <MISP_URL> <API_KEY>"
  exit 1
fi

echo "Testing GET /feeds/index..."
RESPONSE=$(curl -sk -H "Authorization: $MISP_API_KEY" -H "Accept: application/json" "$MISP_URL/feeds/index")

if echo "$RESPONSE" | grep -q '"headers":"[^"]\{4,\}"'; then
    echo "❌ FAIL: Headers leak detected in /feeds/index!"
    exit 1
else
    echo "✅ PASS: Headers are masked or hidden in /feeds/index."
fi

echo "Testing GET /feeds/view/1..."
RESPONSE_VIEW=$(curl -sk -H "Authorization: $MISP_API_KEY" -H "Accept: application/json" "$MISP_URL/feeds/view/1")

if echo "$RESPONSE_VIEW" | grep -q '"headers":"[^"]\{4,\}"'; then
    echo "❌ FAIL: Headers leak detected in /feeds/view!"
    exit 1
else
    echo "✅ PASS: Headers are masked or hidden in /feeds/view."
fi
