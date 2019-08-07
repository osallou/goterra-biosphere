FROM golang:1.11

LABEL maintainer="Olivier Sallou <olivier.sallou@irisa.fr>"

WORKDIR /root

# Set the Current Working Directory inside the container
WORKDIR $GOPATH/src/github.com/osallou/goterra-biosphere

# Copy everything from the current directory to the PWD(Present Working Directory) inside the container
COPY . .
RUN go get -u github.com/golang/dep/cmd/dep
#RUN go get -d -v ./...
RUN dep ensure

# Install the package
RUN go build -ldflags "-X  main.Version=`git rev-parse --short HEAD`" goterra-biosphere.go goterra-openstack.go
RUN cp goterra-biosphere.yml.example goterra.yml
RUN cp biosphere.yml.example biosphere.yml

FROM alpine:latest  
RUN apk --no-cache add ca-certificates
WORKDIR /root/
RUN mkdir /lib64 && ln -s /lib/libc.musl-x86_64.so.1 /lib64/ld-linux-x86-64.so.2
COPY --from=0 /go/src/github.com/osallou/goterra-biosphere/goterra-biosphere .
COPY --from=0 /go/src/github.com/osallou/goterra-biosphere/biosphere.yml .
CMD ["./goterra-biosphere"]
