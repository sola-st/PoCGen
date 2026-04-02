#!/bin/bash

# set -x

dst_dir=$(realpath $1)
shift

if [ ! -d "$dst_dir" ]; then
  mkdir -p "$dst_dir"
  chmod 777 "$dst_dir"
fi

# docker run --name "Aryaz_pocgen_$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)" --user root --rm --env-file .env -v "${dst_dir}:/output:Z" -v '.:/app:ro' gen-poc_mnt $@
docker run --name "Aryaz_pocgen_$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)" --user root --rm --env-file .env -v "${dst_dir}:/output:Z" -v '.:/app:ro' -v /var/run/docker.sock:/var/run/docker.sock gen-poc_mnt $@