#!/usr/bin/env bash
# Qualify the filter sandbox on real ECS Fargate 1.4.0: run the Gateway's
# containment test and its runtime test under "filter" in a task, on x86-64
# and arm64. README.md beside this script says what it needs and proves.
#
# Usage: qualification/fargate/run.sh [command] [architecture...]
#   all       deploy, build and run (the default)
#   deploy    create or update the stack
#   build     build each architecture's image and push it
#   run       run each architecture's task, print its log, fail if it failed
#   local     build this host's image and run it under Docker's default profile
#   teardown  delete the stack, images and logs included
# An architecture is x86_64 or arm64; with none named, both.
# Needs Docker with buildx, and for all but `local` the AWS CLI with
# credentials (AWS_PROFILE) and a region (AWS_REGION, or the profile's).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
cd "$here/../.."

stack=${COUNTERSIGN_QUALIFICATION_STACK:-countersign-fargate-qualification}
command=${1:-all}
shift || true
architectures=("$@")
[ ${#architectures[@]} -gt 0 ] || architectures=(x86_64 arm64)

# Docker's name for an architecture.
platform() {
  case "$1" in
    x86_64) echo linux/amd64 ;;
    arm64) echo linux/arm64 ;;
    *) echo "unknown architecture $1: x86_64 or arm64" >&2; return 1 ;;
  esac
}
for architecture in "${architectures[@]}"; do platform "$architecture" >/dev/null; done

output() {
  aws cloudformation describe-stacks --stack-name "$stack" \
    --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text
}

image() { # architecture, tag, then how to deliver it: --push or --load
  docker buildx build --platform "$(platform "$1")" --provenance=false \
    --file qualification/fargate/Dockerfile \
    --build-arg "REVISION=$(git describe --always --dirty)" --tag "$2" "$3" .
}

teardown() {
  aws cloudformation delete-stack --stack-name "$stack"
  aws cloudformation wait stack-delete-complete --stack-name "$stack"
}

deploy() {
  # A stack whose first deploy failed holds nothing and cannot be updated.
  if [ "$(aws cloudformation describe-stacks --stack-name "$stack" \
    --query 'Stacks[0].StackStatus' --output text 2>/dev/null)" = ROLLBACK_COMPLETE ]; then
    teardown
  fi
  aws cloudformation deploy --stack-name "$stack" --template-file "$here/stack.yaml" \
    --capabilities CAPABILITY_NAMED_IAM --no-fail-on-empty-changeset
}

build() {
  local repository
  repository=$(output RepositoryUri)
  aws ecr get-login-password | docker login --username AWS --password-stdin "${repository%%/*}"
  for architecture in "${architectures[@]}"; do
    image "$architecture" "$repository:$architecture" --push
  done
}

# Start every task first, then wait for each: the architectures run at once.
run() {
  local cluster network group failed=0
  cluster=$(output Cluster)
  group=$(output LogGroup)
  network="awsvpcConfiguration={subnets=[$(output Subnet)],securityGroups=[$(output SecurityGroup)],assignPublicIp=ENABLED}"
  local -A tasks
  for architecture in "${architectures[@]}"; do
    tasks[$architecture]=$(aws ecs run-task --cluster "$cluster" --launch-type FARGATE \
      --platform-version 1.4.0 --task-definition "$stack-$architecture" \
      --network-configuration "$network" --query 'tasks[0].taskArn' --output text)
    echo "started $architecture: ${tasks[$architecture]}"
  done
  for architecture in "${architectures[@]}"; do
    local task=${tasks[$architecture]} code
    aws ecs wait tasks-stopped --cluster "$cluster" --tasks "$task"
    echo "==== Fargate $architecture"
    aws ecs describe-tasks --cluster "$cluster" --tasks "$task" --output text --query \
      'tasks[0].[join(`: `, [`Platform`, platformFamily, platformVersion]), join(`: `, [`Architecture`, attributes[?name==`ecs.cpu-architecture`].value | [0]]), join(`: `, [`Image digest`, containers[0].imageDigest || `none`]), join(`: `, [`Stopped`, stoppedReason || `no reason given`])]' |
      tr '\t' '\n'
    aws logs get-log-events --log-group-name "$group" \
      --log-stream-name "$architecture/qualify/${task##*/}" --start-from-head \
      --query 'events[].message' --output text | tr '\t' '\n' || true
    code=$(aws ecs describe-tasks --cluster "$cluster" --tasks "$task" \
      --query 'tasks[0].containers[0].exitCode' --output text)
    echo "==== Fargate $architecture exit code: $code"
    [ "$code" = 0 ] || failed=1
  done
  return $failed
}

local_run() {
  local architecture
  architecture=$(uname -m)
  [ "$architecture" = aarch64 ] && architecture=arm64
  image "$architecture" "countersign-fargate-qualification:$architecture" --load
  # No --privileged, --cap-add or --security-opt: Docker's default profile,
  # which refuses namespaces as Fargate does.
  docker run --rm "countersign-fargate-qualification:$architecture"
}

case "$command" in
  all) deploy; build; run ;;
  deploy) deploy ;;
  build) build ;;
  run) run ;;
  local) local_run ;;
  teardown) teardown ;;
  *) sed -n '2,/^set -euo/{/^set -euo/d;s/^# \{0,1\}//;p}' "$0" >&2; exit 2 ;;
esac
