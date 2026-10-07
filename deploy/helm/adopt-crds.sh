#!/bin/sh
# Hand Portus's CRDs to a Helm release, once, before the first `helm upgrade`
# to a chart that manages them (the CRDs moved from crds/, which Helm installs
# once and never upgrades, into templates/). Without this the upgrade fails
# with "invalid ownership metadata". Idempotent; CRDs that do not exist yet
# are simply created by the upgrade.
#
#   deploy/helm/adopt-crds.sh <release> <namespace>
set -eu
release=${1:?usage: adopt-crds.sh <release> <namespace>}
namespace=${2:?usage: adopt-crds.sh <release> <namespace>}
kubectl=${KUBECTL:-kubectl}

for crd in $($kubectl get crd -o name | sed -n '/\.portus-gateway\.dev$/p'); do
  $kubectl label "$crd" app.kubernetes.io/managed-by=Helm --overwrite >/dev/null
  $kubectl annotate "$crd" \
    meta.helm.sh/release-name="$release" \
    meta.helm.sh/release-namespace="$namespace" \
    helm.sh/resource-policy=keep --overwrite >/dev/null
  echo "adopted $crd"
done
