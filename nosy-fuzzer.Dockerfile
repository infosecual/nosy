FROM golang:1.21.5
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y vim
RUN apt-get update && apt-get install -y ca-certificates git-core ssh

# install old version of go for common target deps - for example, if you need
# go1.18.6 add this and change go_version in the targets's YAML file:
#RUN go install golang.org/dl/go1.20.3@latest
#RUN go1.20.3 download

RUN mkdir /staging
ENTRYPOINT ["/bin/bash"]

