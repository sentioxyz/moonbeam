#!/bin/bash

cargo build --release

VERSION=v0.47.1-3900-latest

cp target/release/moonbeam .

echo  "FROM moonbeamfoundation/moonbeam-tracing:$VERSION
  COPY --chown=moonbeam moonbeam  /moonbeam
  RUN chmod uog+x /moonbeam/moonbeam*
  " > Dockerfile

docker build . -t ghcr.io/sentioxyz/moonbeam:$VERSION

rm Dockerfile
rm moonbeam

docker push  ghcr.io/sentioxyz/moonbeam:$VERSION
