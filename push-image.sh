# BRANCH=$(git branch --show-current)
# VERSION=${BRANCH#release/}

VERSION=v0.47.1-3900-latest

echo "VERSION: $VERSION"

docker build --build-arg VERSION=$VERSION -f docker/moonbeam-production.Dockerfile . -t ghcr.io/sentioxyz/moonbeam:$VERSION -t ghcr.io/sentioxyz/moonbeam:latest