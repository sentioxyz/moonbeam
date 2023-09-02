#!/bin/bash

cargo build --release

VERSION=v0.39.1-3100-latest

cp target/release/moonbeam .

echo  "FROM moonbeamfoundation/moonbeam-tracing:$VERSION
  COPY --chown=moonbeam moonbeam  /moonbeam
  RUN chmod uog+x /moonbeam/moonbeam*
  " > Dockerfile

docker build . -t us-west1-docker.pkg.dev/sentio-352722/sentio/moonbeam:$VERSION

rm Dockerfile
rm moonbeam

docker push  us-west1-docker.pkg.dev/sentio-352722/sentio/moonbeam:$VERSION