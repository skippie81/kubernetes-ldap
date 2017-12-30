FROM golang:alpine as builder
RUN apk add -U curl && apk add -U git && apk add -U make
COPY  . /go/src/kubernetes-ldap
WORKDIR /go/src/kubernetes-ldap
RUN make

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /go/src/kubernetes-ldap/bin/kubernetes-ldap /kubernetes-ldap/kubernetes-ldap
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["kubernetes-ldap"]
