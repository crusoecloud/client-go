#!/usr/bin/env bash
set -e

GITLAB_TOKEN=$1
CI_COMMIT_SHA=$2
CI_PROJECT_ID=$3
MAJOR_VERSION=$4
MINOR_VERSION=$5
TAG_PREFIX=$6

# find the latest tag
NEW_VERSION="${TAG_PREFIX}v${MAJOR_VERSION}.${MINOR_VERSION}.0"
git fetch -q --tags
tags=$(git tag -l ${TAG_PREFIX}v${MAJOR_VERSION}.${MINOR_VERSION}.* --sort=-version:refname)
if [[ ! -z "$tags" ]]; then
  arr=(${tags})
  for val in ${arr[@]}; do
    if [[ "$val" =~ ^${TAG_PREFIX}v${MAJOR_VERSION}+\.${MINOR_VERSION}\.[0-9]+$ ]]; then
      prev_build=$(echo ${val} | cut -d. -f3)
      new_build=$((prev_build+1))
      NEW_VERSION="${TAG_PREFIX}v${MAJOR_VERSION}.${MINOR_VERSION}.${new_build}"
      break
    fi
  done
fi

echo "Adding git tag for version ${NEW_VERSION} via curl POST"
resp=$(curl -s --request POST --header "PRIVATE-TOKEN: ${GITLAB_TOKEN}" --header "Content-Type: application/json" \
  --data "{\"tag_name\": \"${NEW_VERSION}\", \"ref\": \"${CI_COMMIT_SHA}\", \"name\": \"Release ${NEW_VERSION}\"}" \
  https://gitlab.com/api/v4/projects/${CI_PROJECT_ID}/releases)
echo $resp | jq

# check if the request was successful
if [[ $(echo $resp | jq .name) == "null" ]]; then
  exit 1
fi
