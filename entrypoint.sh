#!/bin/sh

_CMD=/kubernetes-ldap/kubernetes-ldap

if [ $1 == "kubernetes-ldap" ]
then
  # get args from env vars
  env | egrep "KUBERNETES_LDAP_"
  ARGS=$( env | egrep "^KUBERNETES_LDAP_" | sed 's/^KUBERNETES_LDAP_/--/g' | sed 's/_/-/g' | tr '\n' ' ' )
  echo "running: $_CMD $ARGS ${@:2}"
  $_CMD $ARGS ${@:2}
else
  $@
fi