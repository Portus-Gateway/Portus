# Portus on an apple/container machine (no Docker Desktop)

A `container machine` is a persistent Linux VM under macOS's Virtualization
framework with your home directory shared at the same path. This directory
turns one into a single-node k3s for building, deploying and benchmarking
Portus with nothing else installed on the Mac: no Docker Desktop, no Colima.

Two things the stock setup lacks, and how this fills them:

1. **The guest kernel.** apple/container boots the Kata Containers kernel,
   which has no nftables, no vxlan and no bridge netfilter, so kube-proxy and
   flannel cannot work. `kernel/` builds the same Kata kernel with one extra
   config fragment (`portus-k8s.conf`) and `container system kernel set`
   installs it as the default for every machine and container. Same slim,
   VM-tuned kernel; the Kubernetes options built in.
2. **The rootfs.** Machines need `/sbin/init`; `Dockerfile` makes an Ubuntu
   24.04 image with systemd as PID 1, k3s as a service (traefik and servicelb
   off), and nerdctl + buildkitd pointed at k3s's containerd in the `k8s.io`
   namespace, so `docker build` inside the machine produces images the
   cluster can run without an import step.

## One-time setup

```bash
# 1. Kernel (about 12 min in a throwaway container)
container run --rm --cpus 10 --memory 8G -v $PWD/deploy/machine/kernel:/kernel \
  ubuntu:24.04 bash /kernel/build-kata-kernel.sh
container system kernel set --binary deploy/machine/kernel/out/Image --force

# 2. Rootfs image and the machine
container build -t portus/machine:dev -f deploy/machine/Dockerfile deploy/machine
container machine create portus/machine:dev --name portus --cpus 10 --memory 12G

# 3. kubeconfig for the host (the machine's IP is in `container machine ls`)
container machine run -n portus --user root cat /etc/rancher/k3s/k3s.yaml \
  | sed "s#127.0.0.1#$(container machine ls | awk '/^portus /{print $4}')#" \
  > ~/.config/k3d/kubeconfig-portus-machine.yaml
```

## Daily use

```bash
export KUBECONFIG=~/.config/k3d/kubeconfig-portus-machine.yaml
make build deploy PLATFORM=machine          # nerdctl builds inside the machine, helm from the host
make bench-backend bench-portus bench-traffic PLATFORM=machine
container machine stop portus            # `container machine run -n portus ...` boots it again on demand
```

Everything after the build step (helm, kubectl, the bench and conformance
targets) runs from the host against the kubeconfig, exactly as with k3d.

## What to expect

- Needs apple/container 1.4.1 or later (`container system start` must be
  running) and macOS 26 on Apple silicon; the kernel is arm64 only.
- `container machine create` boots the machine twice and the DHCP address can
  change between those boots. k3s advertises the address it sees at start, so
  on a fresh machine it spends about a minute reconnecting to its old address
  and the three system pods restart once or twice before settling. It heals
  itself; `k3s-wait-ip.conf` makes k3s wait for a global IPv4 address before
  starting so a slow lease cannot leave it on no address at all.
- The machine's address is what the host kubeconfig points at; after a
  `container machine start` check `container machine ls` and regenerate the
  kubeconfig if the address moved.
- A cold `make build` inside the machine takes about 8 minutes (cargo cache
  mounts live on the machine's disk and survive restarts, not deletes).
- **Pod MTU.** The vz NIC has MTU 1280, so flannel would give pods 1230 and
  every large response costs 18 % more packets than on k3d (1450). Flannel runs
  on `node0` (MTU 65535) instead; on one node the overlay carries nothing and
  pods get MTU 65485. Measured 2026-09-11 with one Portus build: request path
  142k QPS / p99 0.35 ms at 30k (level with Docker Desktop's VM), download
  1 MiB 7,273 QPS (7.6 GB/s) vs 5,654 on Docker's VM, HTTPS 1 KB 91k vs 77k,
  h2c 1 MiB 5,305 vs 3,500. Colima with Ubuntu's generic kernel was 10–30 %
  below Docker's VM. See `benchmarks/` and the Grimoire "Local Bench Box" doc.
