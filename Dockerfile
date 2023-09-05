ARG BASE_FINAL_IMAGE=alpine:3.17
ARG BASE_BUILD_IMAGE=golang:1.19-alpine
ARG ANCHORE_VERSION=v1.8.0
######## Build ########
FROM ${BASE_BUILD_IMAGE} AS GOLANG
WORKDIR /src
ARG USER
ARG TOKEN
RUN apk --no-cache add make git gcc libtool musl-dev ca-certificates dumb-init \
    && go install golang.org/x/vuln/cmd/govulncheck@latest \
    && go env -w GOPRIVATE=github.com/cloudbees-compliance/* \
    && git config --global url."https://${USER}:${TOKEN}@github.com".insteadOf  "https://github.com" 
COPY go.mod go.sum /src/
RUN go mod download && go mod verify 
COPY . /src
# run tests and govulncheck (but dont fail build if they fail)
RUN go test -short ./... \
    && govulncheck ./... || true
# build statically linked binary, include GIT details in ldflags
RUN GIT_COMMIT=$(git rev-list -1 HEAD) \
    && BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
    && GIT_DESCRIBE=$(git describe --tags) \
    && go build -o /tmp/myapp \
        -ldflags="-linkmode 'external' -extldflags '-static' \
        -X 'main.GitCommitId=${GIT_COMMIT}' \
        -X 'main.BuildDate=${BUILD_DATE}' \
        -X 'main.GitDescribe=${GIT_DESCRIBE}'" \
    && go version /tmp/myapp
##############Install Dependency##################################
FROM alpine:3.17 as deps
WORKDIR /app
ARG ANCHORE_VERSION
RUN apk --no-cache add curl \
    && curl -sSfL  https://anchorectl-releases.anchore.io/anchorectl/install.sh  | sh -s -- -b /app ${ANCHORE_VERSION} 

######## Final Image  ############################################
FROM ${BASE_FINAL_IMAGE}
WORKDIR /app/
LABEL cbc.deps.anchore_version=${ANCHORE_VERSION}

# userid and groupid to run as
ARG UID=1000
ARG GID=1000
# create non-priv user and group and set homedir as /tmp
RUN apk --no-cache add ca-certificates wget
RUN addgroup -g "${GID}" non-priv \
  && adduser -h  /tmp  -u "${UID}" -g "${GID}" non-priv
# create tmp-pre-boot folder to allow copying into /tmp on bootup and fix permissions
# before changing user (but user must have been created already)
RUN mkdir /tmp-pre-boot || true && chown -R non-priv:non-priv /tmp-pre-boot
USER non-priv

COPY --chown=${UID}:${GID} --from=GOLANG /src/entrypoint.sh /app/entrypoint.sh
COPY --chown=${UID}:${GID} --from=GOLANG /tmp/myapp /app/myapp
COPY --chown=${UID}:${GID} --from=deps /app/anchorectl /app/anchorectl

# move /tmp content into /tmp-pre-boot so entrypoint.sh can copy it back after mounting /tmp
RUN cp -R /tmp/. /tmp-pre-boot/

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["/app/myapp"]