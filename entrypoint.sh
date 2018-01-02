#!/bin/sh

_CMD=/kubernetes-ldap/kubernetes-ldap

if [ $1 == "kubernetes-ldap" ]
then
  # get args from env vars
  env | egrep "K8S_LDAP_"
  ARGS=$( env | egrep "^K8S_LDAP_" | sed 's/^K8S_LDAP_/--/g' | sed 's/_/-/g' | tr '\n' ' ' )
  echo "running: $_CMD $ARGS"
  $_CMD $ARGS --logtostderr --ldap-skip-tls-verification
else
  $@
fi
