#!/bin/bash

mkdir -p bundle/lib
cp zig-out/lib/* bundle/lib/
cp temp/libsolfuzz_agave.so bundle/lib

mkdir bundle/target
cp temp/fuzz_sol* bundle/target
cp target/*.fc bundle/target

commit_id=$(git log --format="%H" -n 1)
echo "{\"commit\": \"$commit_id\", \"checkouts\": [
{\"repoUrl\": \"https://github.com/firedancer-io/solfuzz-agave\", \"commit\":\"$(cat ./temp/libsolfuzz-agave.so.hash)\"},
{\"repoUrl\": \"https://github.com/Syndica/sig-fuzz\", \"commit\":\"$commit_id\"}]}"
> "bundle/fuzzcorp.json"

cd bundle && zip -r fuzz.zip *