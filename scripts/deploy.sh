#!/usr/bin/env bash
#
# Deploy dney-mcp to ECS and VERIFY it.
#
# This service had no deploy script, and on 2026-07-29 a broken image was pushed
# and rolled out unnoticed: mcp 2.0.0 had moved mcp.server.fastmcp the day
# before, the floating "mcp[cli]>=1.9.0" resolved to it at build time, and the
# container crash-looped on import for 25 days. Nothing checked that the thing
# now serving traffic could actually serve traffic.
#
# So the last step here is not "the service stabilized" — ECS reports stable for
# a service that is quietly failing its health checks too. It is an HTTP probe
# of the public endpoint, asserting both that /health answers AND that /mcp
# still demands auth, so a deploy cannot pass by serving an unauthenticated app.
#
# Usage:
#   scripts/deploy.sh v0.5.2-lexington-something
set -euo pipefail

die() { printf '\n\033[31mFAILED:\033[0m %s\n' "$1" >&2; exit 1; }
step() { printf '\n\033[36m==> %s\033[0m\n' "$1"; }

# Infrastructure ids are not in this repo (SCRUM-554: it is public). Set them in
# the environment, or in a private env file outside the tree named by
# DNEY_DEPLOY_ENV (default ~/.dney/mcp-deploy.env), which is sourced if present.
DEPLOY_ENV_FILE="${DNEY_DEPLOY_ENV:-$HOME/.dney/mcp-deploy.env}"
if [[ -f "$DEPLOY_ENV_FILE" ]]; then
  # shellcheck source=/dev/null
  set -a; . "$DEPLOY_ENV_FILE"; set +a
fi
for v in CLUSTER SERVICE REGION REPO HEALTH_URL MCP_URL; do
  [[ -n "${!v:-}" ]] || die "$v is not set (environment or $DEPLOY_ENV_FILE). Nothing has been built or pushed."
done
REGISTRY="${REPO%%/*}"

TAG="${1:-}"
[[ -n "$TAG" ]] || die "no image tag given. Usage: scripts/deploy.sh <image-tag>"

# An immutable repo cannot overwrite a tag, and deploying an OLD image under a
# tag you believe is new is worse than failing here.
if aws ecr describe-images --repository-name "${REPO#*/}" --region "$REGION" \
     --image-ids "imageTag=$TAG" >/dev/null 2>&1; then
  die "tag $TAG already exists in ECR (repo is immutable) — pick a new tag"
fi

[[ -z "$(git status --porcelain)" ]] || die "working tree is dirty — commit or stash first"

step "Tests"
PYTHON_BIN=""
for c in ".venv/bin/python" "python3"; do
  if command -v "$c" >/dev/null 2>&1 || [[ -x "$c" ]]; then
    "$c" -c "import asgard_mcp" >/dev/null 2>&1 && PYTHON_BIN="$c" && break
  fi
done
[[ -n "$PYTHON_BIN" ]] || die "no interpreter with asgard_mcp installed"
"$PYTHON_BIN" -m pytest tests/ -q || die "tests failed — not deploying"

step "Build + push ($TAG)"
# ARM64 is not optional: Fargate runs arm64 here and a mismatched image dies at
# runtime with 'exec format error'. The Dockerfile's import smoke test also runs
# during this build, so a bad dependency resolution fails HERE rather than in
# production.
aws ecr get-login-password --region "$REGION" \
  | docker login --username AWS --password-stdin "$REGISTRY" >/dev/null
docker buildx build --platform linux/arm64 -t "$REPO:$TAG" --push . \
  || die "image build/push failed (the build-time import check may have caught a bad resolve)"

step "Register task definition"
CURRENT="$(aws ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" \
  --region "$REGION" --query 'services[0].taskDefinition' --output text)"
aws ecs describe-task-definition --task-definition "$CURRENT" --region "$REGION" \
  --query 'taskDefinition' --output json > /tmp/dney-mcp-td.json
IMAGE="$REPO:$TAG" python3 - <<'PY' || die "could not build task definition"
import json, os
td = json.load(open("/tmp/dney-mcp-td.json"))
for k in ("taskDefinitionArn","revision","status","requiresAttributes","compatibilities",
          "registeredAt","registeredBy","deregisteredAt"):
    td.pop(k, None)
td["containerDefinitions"][0]["image"] = os.environ["IMAGE"]
json.dump(td, open("/tmp/dney-mcp-td-new.json","w"))
PY
NEW_TD="$(aws ecs register-task-definition --region "$REGION" \
  --cli-input-json file:///tmp/dney-mcp-td-new.json \
  --query 'taskDefinition.taskDefinitionArn' --output text)" || die "register failed"
echo "registered $NEW_TD"

step "Roll the service"
aws ecs update-service --cluster "$CLUSTER" --service "$SERVICE" \
  --task-definition "$NEW_TD" --region "$REGION" >/dev/null || die "update-service failed"
aws ecs wait services-stable --cluster "$CLUSTER" --services "$SERVICE" --region "$REGION" \
  || die "service did not stabilize — check CloudWatch /ecs/dney-mcp"

step "Verify it actually serves"
RUNNING="$(aws ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" \
  --region "$REGION" --query 'services[0].runningCount' --output text)"
[[ "$RUNNING" == "1" ]] || die "runningCount=$RUNNING — the task is not up"

HEALTH_CODE="$(curl -s -o /tmp/dney-mcp-health -w '%{http_code}' -m 30 "$HEALTH_URL" || echo 000)"
[[ "$HEALTH_CODE" == "200" ]] || die "$HEALTH_URL returned $HEALTH_CODE (crash-loop? check /ecs/dney-mcp)"
grep -q '"status"' /tmp/dney-mcp-health || die "health body is not the expected JSON"

# 401 is the PASS here. A 200 would mean the endpoint stopped requiring auth.
MCP_CODE="$(curl -s -o /dev/null -w '%{http_code}' -m 30 "$MCP_URL" || echo 000)"
[[ "$MCP_CODE" == "401" || "$MCP_CODE" == "403" ]] \
  || die "$MCP_URL returned $MCP_CODE; expected 401/403 — auth may be broken or the app is down"

printf '\n\033[32mDEPLOYED AND VERIFIED:\033[0m %s — /health 200, /mcp %s\n' "$TAG" "$MCP_CODE"
