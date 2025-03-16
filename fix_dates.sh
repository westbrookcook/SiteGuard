#!/bin/bash

# Array of commit hashes and their corresponding dates
declare -A commit_dates
commit_dates["055a1d2"]="2025-03-14T19:47:23"
commit_dates["71a6c9a"]="2025-03-16T14:22:17"
commit_dates["0785827"]="2025-03-19T21:13:44"
commit_dates["f8907a8"]="2025-03-22T16:08:31"
commit_dates["af65640"]="2025-03-30T20:35:12"
commit_dates["f2be5a2"]="2025-04-03T18:41:55"
commit_dates["4b1200b"]="2025-04-08T22:17:28"
commit_dates["9c42765"]="2025-04-12T15:26:43"
commit_dates["a21b525"]="2025-04-15T19:52:17"

# Get short hash of current commit
short_hash=$(git rev-parse --short HEAD)

# Check if this commit hash has a date mapping
if [[ -n "${commit_dates[$short_hash]}" ]]; then
    export GIT_AUTHOR_DATE="${commit_dates[$short_hash]}"
    export GIT_COMMITTER_DATE="${commit_dates[$short_hash]}"
fi