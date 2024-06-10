#!/bin/bash

VERSION=v0.36.1-2801-latest

cp target/release/moonbeam .

echo  "FROM purestake/moonbeam-tracing:$VERSION
  COPY --chown=moonbeam moonbeam  /moonbeam
  RUN chmod uog+x /moonbeam/moonbeam*
  " > Dockerfile

docker build . -t us-west1-docker.pkg.dev/sentio-352722/sentio/moonbeam:$VERSION

rm Dockerfile
rm moonbeam

docker push  us-west1-docker.pkg.dev/sentio-352722/sentio/moonbeam:$VERSION