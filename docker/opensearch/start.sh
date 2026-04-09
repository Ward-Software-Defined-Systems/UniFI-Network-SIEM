#!/bin/bash
docker compose -f "$(dirname "$0")/docker-compose.yml" up -d
echo "Waiting for OpenSearch..."
until curl -sk -u admin:S!em_Secure9200 https://localhost:9200 >/dev/null 2>&1; do sleep 1; done
echo "OpenSearch ready at https://localhost:9200"
