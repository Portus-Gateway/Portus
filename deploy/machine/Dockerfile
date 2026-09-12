# Root filesystem for an apple/container "machine" that runs a single-node k3s
# for Portus development and benchmarking on macOS without Docker Desktop.
#
#   container build -t portus/machine:dev -f deploy/machine/Dockerfile deploy/machine
#   container machine create portus/machine:dev --name portus --cpus 10 --memory 12G
#
# systemd is PID 1 (machines need /sbin/init; systemd parks itself in
# init.scope, which is what lets the kubelet delegate cgroup controllers).
# k3s runs as a systemd service with its own containerd; nerdctl + buildkitd
# build images straight into that containerd's k8s.io namespace, so nothing
# is imported. The guest kernel must carry the Kubernetes networking options
# (see kernel/README.md): the stock apple/container kernel does not.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus udev kmod iproute2 iptables nftables ethtool \
      ca-certificates curl wget git make python3 ripgrep jq openssl zstd sudo \
    && rm -rf /var/lib/apt/lists/* \
    && systemctl mask systemd-resolved.service systemd-timesyncd.service getty@tty1.service console-getty.service
# k3s: installed but not started at build time; the unit is enabled for boot.
ARG K3S_VERSION=v1.35.0+k3s1
RUN curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION=${K3S_VERSION} INSTALL_K3S_SKIP_START=true INSTALL_K3S_SKIP_ENABLE=true \
      INSTALL_K3S_EXEC="server --disable traefik --disable servicelb --write-kubeconfig-mode 644" sh -
# nerdctl + buildkitd against k3s's containerd (k8s.io namespace).
ARG NERDCTL_VERSION=2.3.1
RUN curl -sfL https://github.com/containerd/nerdctl/releases/download/v${NERDCTL_VERSION}/nerdctl-full-${NERDCTL_VERSION}-linux-arm64.tar.gz \
      | tar -xz -C /tmp && install -m755 /tmp/bin/nerdctl /tmp/bin/buildkitd /tmp/bin/buildctl /usr/local/bin/ \
    && ln -s /usr/local/bin/nerdctl /usr/local/bin/docker && rm -rf /tmp/bin /tmp/lib /tmp/libexec /tmp/share
COPY buildkitd.service /etc/systemd/system/buildkitd.service
COPY k3s-node-identity.conf /etc/systemd/system/k3s.service.d/node-identity.conf
COPY 10-node.netdev 10-node.network /etc/systemd/network/
RUN systemctl enable systemd-networkd.service
COPY nerdctl.toml /etc/nerdctl/nerdctl.toml
RUN systemctl enable k3s.service buildkitd.service
# helm
RUN curl -sfL https://get.helm.sh/helm-v3.19.0-linux-arm64.tar.gz | tar -xz -C /tmp && install -m755 /tmp/linux-arm64/helm /usr/local/bin/helm && rm -rf /tmp/linux-arm64
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
