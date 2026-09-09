MISE        := mise exec --
K3D_CLUSTER ?= portus-local
# k3s (Kubernetes) version for the local cluster. Gateway API v1.6 CRDs need
# Kubernetes >= 1.32 (CEL format helpers); track the latest stable k3s.
K3S_IMAGE   ?= rancher/k3s:v1.36.4-k3s1
HELM_RELEASE?= portus
HELM_CHART  := deploy/helm
NAMESPACE   ?= portus

CONTROLLER_REPO  := portus-gateway/controller
CONTROLLER_TAG   := dev
CONTROLLER_IMAGE := $(CONTROLLER_REPO):$(CONTROLLER_TAG)
DATAPLANE_REPO   := portus-gateway/dataplane
DATAPLANE_TAG    := dev
DATAPLANE_IMAGE  := $(DATAPLANE_REPO):$(DATAPLANE_TAG)
PROXY_IMAGE      := portus/proxy:dev
NODES       ?= 10
RPS         ?= 1000
PAYLOAD_KB  ?= 0
DURATION    ?= 30s
WORKERS     ?= 64


.PHONY: all k3d-up k3d-down build-controller build-dataplane build-proxy build deploy conformance-image conformance-run conformance-clean \
       gateway-api-crds clean disk-check disk-report disk-prune \
       bench-backend bench-portus bench-agentgateway bench-envoy-gateway bench-nginx bench-wait bench-traffic bench-latency bench-download bench-upload bench-https bench-h2 bench-teardown \
       bench-tools-image bench-attached-routes bench-probe bench-route-change bench-backend-failover bench-route-scale

all: k3d-up build deploy

# ── Disk ───────────────────────────────────────────────────────────────────────
# Every build cycle leaves an image tag on the host, a second copy inside the
# k3d node (`k3d image import` never removes the previous one), BuildKit cache
# and a debug `target/`. A full disk has corrupted Docker's store and the k3s
# datastore four times, so image builds and imports refuse to start below
# DISK_MIN_FREE_GB and `disk-prune` is how the churn is reclaimed.
DISK_MIN_FREE_GB ?= 20
K3D_NODE := k3d-$(K3D_CLUSTER)-server-0

disk-check:
	@free=$$(df -g "$$HOME" | awk 'NR==2 {print $$4}'); \
	if [ "$$free" -lt $(DISK_MIN_FREE_GB) ]; then \
	  echo "disk-check: $$free GiB free on the host, need $(DISK_MIN_FREE_GB); run 'make disk-prune' (and 'make disk-report' to see what is using it)"; exit 1; fi

disk-report:
	@echo "host: $$(df -h "$$HOME" | awk 'NR==2 {print $$4 " free of " $$2}')"
	@raw="$$HOME/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw"; [ -f "$$raw" ] && echo "Docker.raw: $$(du -h "$$raw" | cut -f1) on disk"
	@docker system df 2>/dev/null || true
	@docker exec $(K3D_NODE) sh -c 'echo "k3d node image store: $$(du -sh /var/lib/rancher/k3s/agent/containerd 2>/dev/null | cut -f1)"' 2>/dev/null || true
	@[ -d target ] && echo "cargo target/: $$(du -sh target | cut -f1)" || true

# Removes: tags of our images (controller, dataplane, conformance runner, bench
# tools) that the cluster is not configured to run, on the host and inside the
# k3d node; dangling images; BuildKit records unused for three days (the cargo
# and go cache mounts are touched by every build and survive). The images to
# keep come from the chart: the controller Deployment's image and the dataplane
# image it provisions (`PORTUS_DATAPLANE_IMAGE`), plus the runner and bench
# tools tags the Makefile targets use, so an idle cluster with no Gateway does
# not lose the dataplane image it will need for the next one.
OUR_IMAGES := ^(portus-gateway|portus)/gateway-?(controller|dataplane)|^portus/(conformance|bench-tools)
disk-prune:
	@keep="$$($(MISE) kubectl get deploy -n $(NAMESPACE) -o jsonpath='{.items[*].spec.template.spec.containers[*].image} {.items[*].spec.template.spec.containers[*].env[?(@.name=="PORTUS_DATAPLANE_IMAGE")].value}' 2>/dev/null) $(CONTROLLER_IMAGE) $(DATAPLANE_IMAGE) $(CONFORMANCE_IMAGE) $(BENCH_TOOLS_IMAGE)"; \
	echo "keeping: $$keep"; \
	for img in $$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | awk '$$0 ~ "$(OUR_IMAGES)"'); do \
	  case " $$keep " in *" $$img "*) ;; *) docker rmi "$$img" >/dev/null 2>&1 && echo "removed $$img";; esac; done; \
	for img in $$(docker exec $(K3D_NODE) crictl images -o json 2>/dev/null | python3 -c 'import sys,json; [print(t) for i in json.load(sys.stdin)["images"] for t in i["repoTags"]]' | sed 's#^docker.io/##' | awk '$$0 ~ "$(OUR_IMAGES)"'); do \
	  case " $$keep " in *" $$img "*) ;; *) docker exec $(K3D_NODE) crictl rmi "docker.io/$$img" >/dev/null 2>&1 && echo "removed $$img from $(K3D_NODE)";; esac; done
	@docker image prune -f >/dev/null 2>&1 || true
	@docker builder prune -f --filter until=72h >/dev/null 2>&1 || true
	@$(MAKE) --no-print-directory disk-report

# ── Cluster ────────────────────────────────────────────────────────────────────

k3d-up:
	@$(MISE) k3d cluster list -o json | python3 -c "import sys,json; clusters=[c['name'] for c in json.load(sys.stdin)]; sys.exit(0 if '$(K3D_CLUSTER)' in clusters else 1)" 2>/dev/null \
		&& echo "cluster $(K3D_CLUSTER) already exists" \
		|| $(MISE) k3d cluster create $(K3D_CLUSTER) \
			--image $(K3S_IMAGE) \
			--k3s-arg "--disable=traefik@server:0" \
			--wait

k3d-down:
	$(MISE) k3d cluster delete $(K3D_CLUSTER)

# ── Build ──────────────────────────────────────────────────────────────────────

build: build-controller build-dataplane

build-controller: disk-check
	docker build -t $(CONTROLLER_IMAGE) -f deploy/docker/Dockerfile.controller .

build-dataplane: disk-check
	docker build -t $(DATAPLANE_IMAGE) -f deploy/docker/Dockerfile.dataplane .

build-proxy: disk-check
	docker build -t $(PROXY_IMAGE) -f deploy/docker/Dockerfile.proxy .

build-proxy-linux:
	docker buildx build --platform linux/amd64 -t $(PROXY_IMAGE)-linux -f deploy/docker/Dockerfile.proxy .

# ── Deploy ─────────────────────────────────────────────────────────────────────

GATEWAY_API_VERSION ?= v1.6.2
# Installs the pinned experimental CRD bundle. Skipped when the cluster already
# has this bundle version: re-applying can fail on older API servers (the v1.6
# bundle uses CEL helpers such as format.dns1123Label() that need Kubernetes 1.32).
gateway-api-crds:
	@installed=$$($(MISE) kubectl get crd gateways.gateway.networking.k8s.io -o jsonpath='{.metadata.annotations.gateway\.networking\.k8s\.io/bundle-version}' 2>/dev/null); \
	if [ "$$installed" = "$(GATEWAY_API_VERSION)" ]; then \
		echo "Gateway API CRDs $(GATEWAY_API_VERSION) already installed"; \
	else \
		$(MISE) kubectl apply --server-side --force-conflicts -f https://github.com/kubernetes-sigs/gateway-api/releases/download/$(GATEWAY_API_VERSION)/experimental-install.yaml; \
	fi

# Dev deploy: one dataplane Deployment + Service per Gateway. Gateway addresses
# are ClusterIPs, so the conformance suite runs in-cluster (`make conformance-run`).
deploy: gateway-api-crds disk-check
	$(MISE) k3d image import $(CONTROLLER_IMAGE) -c $(K3D_CLUSTER)
	$(MISE) k3d image import $(DATAPLANE_IMAGE) -c $(K3D_CLUSTER)
	$(MISE) helm upgrade --install $(HELM_RELEASE) $(HELM_CHART) \
		--namespace $(NAMESPACE) \
		--create-namespace \
		--set controller.image.repository=$(CONTROLLER_REPO) \
		--set controller.image.tag=$(CONTROLLER_TAG) \
		--set controller.image.pullPolicy=Never \
		--set dataplane.image.repository=$(DATAPLANE_REPO) \
		--set dataplane.image.tag=$(DATAPLANE_TAG) \
		--set dataplane.image.pullPolicy=Never \
		--set dataplane.service.type=ClusterIP \
		--set dataplane.replicasPerGateway=1 \
		--wait

# ── Benchmark (howardjohn/gateway-api-bench traffic method, in-cluster) ─────
# Backend: howardjohn/hyper-server (deploy/bench/backend.yaml). One Gateway +
# HTTPRoute per implementation in the `bench` namespace (deploy/bench/<impl>.yaml).
# Load: howardjohn/benchtool (fortio) as a Job inside the cluster, so per-Gateway
# ClusterIP addresses are reachable and the load generator sits next to the
# proxies like the upstream harness. Run one implementation at a time:
#
#   make bench-backend                       # backend + namespace
#   make bench-portus                        # Portus Gateway (3 dataplane replicas)
#   make bench-traffic GATEWAYS=bench/portus  # connection ladder, unlimited QPS
#   make bench-latency GATEWAYS=bench/portus  # fixed 30k QPS, p99
#   make bench-agentgateway && make bench-traffic GATEWAYS=bench/agentgateway
#   make bench-teardown
BENCH_REPLICAS ?= 3
BENCH_CPU      ?= 2
BENCH_LADDER   ?= 1,2,4,8,16,32,64,128,256
BENCH_DURATION ?= 10
BENCH_QPS      ?= 30000
BENCH_LATENCY_CONNS ?= 64
BENCH_RESULTS  ?= benchmarks/results
GATEWAYS       ?= bench/portus

bench-backend:
	$(MISE) kubectl apply -f deploy/bench/backend.yaml -f deploy/bench/echo-backend.yaml
	$(MISE) kubectl -n bench rollout status deploy/backend --timeout=120s
	$(MISE) kubectl -n bench rollout status deploy/echo --timeout=120s
	@$(MISE) kubectl -n bench get secret bench-tls >/dev/null 2>&1 || { \
	  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj '/CN=bench.example.com' \
	    -keyout /tmp/bench-tls.key -out /tmp/bench-tls.crt >/dev/null 2>&1 && \
	  $(MISE) kubectl -n bench create secret tls bench-tls --cert=/tmp/bench-tls.crt --key=/tmp/bench-tls.key; }

# Portus: bump the dataplane template so each bench Gateway gets BENCH_REPLICAS
# pods with BENCH_CPU cores requested (worker threads follow the CPU request).
bench-portus: bench-backend
	$(MISE) helm upgrade $(HELM_RELEASE) $(HELM_CHART) -n $(NAMESPACE) --reuse-values \
		--set dataplane.replicasPerGateway=$(BENCH_REPLICAS) \
		--set dataplane.resources.requests.cpu=$(BENCH_CPU) --wait
	$(MISE) kubectl apply -f deploy/bench/portus.yaml
	$(MAKE) bench-wait GATEWAYS=bench/portus

# agentgateway (its own chart since kgateway 2.2 stopped bundling it; class `agentgateway`).
AGENTGATEWAY_VERSION ?= v1.5.0
bench-agentgateway: bench-backend
	$(MISE) helm upgrade -i --create-namespace --namespace agentgateway-system --version $(AGENTGATEWAY_VERSION) agentgateway-crds oci://cr.agentgateway.dev/charts/agentgateway-crds
	$(MISE) helm upgrade -i --namespace agentgateway-system --version $(AGENTGATEWAY_VERSION) agentgateway oci://cr.agentgateway.dev/charts/agentgateway --wait
	$(MISE) kubectl apply -f deploy/bench/agentgateway.yaml
	$(MAKE) bench-wait GATEWAYS=bench/agentgateway
	$(MISE) kubectl -n bench scale deploy agentgateway --replicas=$(BENCH_REPLICAS)
	$(MISE) kubectl -n bench rollout status deploy/agentgateway --timeout=120s

bench-envoy-gateway: bench-backend
	$(MISE) helm upgrade --install --create-namespace --namespace envoy-gateway-system --version v1.5.3 eg oci://docker.io/envoyproxy/gateway-helm \
		--set config.envoyGateway.provider.kubernetes.deploy.type=GatewayNamespace --set deployment.envoyGateway.resources.limits.memory=null --wait
	$(MISE) kubectl apply -f deploy/bench/envoy-gateway.yaml
	$(MAKE) bench-wait GATEWAYS=bench/envoy-gateway

bench-nginx: bench-backend
	$(MISE) helm upgrade --install nginx --namespace nginx-system --create-namespace --version 2.1.4 oci://ghcr.io/nginx/charts/nginx-gateway-fabric --wait
	$(MISE) kubectl apply -f deploy/bench/nginx.yaml
	$(MAKE) bench-wait GATEWAYS=bench/nginx

# Wait until every Gateway in GATEWAYS has an address and Programmed=True.
bench-wait:
	@for gw in $(GATEWAYS); do ns=$${gw%/*}; name=$${gw#*/}; \
	  for i in $$(seq 1 60); do \
	    addr=$$($(MISE) kubectl get gateway -n $$ns $$name -o jsonpath='{.status.addresses[0].value}' 2>/dev/null); \
	    prog=$$($(MISE) kubectl get gateway -n $$ns $$name -o jsonpath='{.status.conditions[?(@.type=="Programmed")].status}' 2>/dev/null); \
	    [ -n "$$addr" ] && [ "$$prog" = "True" ] && { echo "$$gw ready at $$addr"; break; }; sleep 2; \
	  done; done

# Resolve GATEWAYS to benchtool targets and run the Job, streaming its log to BENCH_RESULTS.
define bench_run
	@targets=""; for gw in $(GATEWAYS); do ns=$${gw%/*}; name=$${gw#*/}; \
	  addr=$$($(MISE) kubectl get gateway -n $$ns $$name -o jsonpath='{.status.addresses[0].value}'); \
	  [ -n "$$addr" ] || { echo "$$gw has no address"; exit 1; }; \
	  targets="$$targets$${targets:+,}http://$$addr#$$name"; done; \
	echo "==> targets: $$targets"; \
	$(MISE) kubectl delete job benchtool -n bench --ignore-not-found --wait=true >/dev/null 2>&1; \
	BENCH_TARGETS="$$targets" BENCH_ARGS="$(1)" python3 deploy/bench/render-job.py | $(MISE) kubectl apply -f - >/dev/null; \
	for i in $$(seq 1 60); do phase=$$($(MISE) kubectl get pod -l app.kubernetes.io/name=benchtool -n bench -o jsonpath='{.items[0].status.phase}' 2>/dev/null); \
	  [ "$$phase" = "Running" ] || [ "$$phase" = "Succeeded" ] || [ "$$phase" = "Failed" ] && break; sleep 1; done; \
	mkdir -p $(BENCH_RESULTS); out=$(BENCH_RESULTS)/$$(date +%Y%m%d-%H%M%S)-$(2)-$$(echo "$(GATEWAYS)" | tr ' /' '_-').txt; \
	KUBECTL="$(MISE) kubectl" python3 deploy/bench/sample-top.py $$out.top.tsv 5 & sampler=$$!; \
	$(MISE) kubectl logs -f job/benchtool -n bench | tee $$out; \
	kill $$sampler 2>/dev/null; wait $$sampler 2>/dev/null; \
	echo "==> resource usage while running (kubectl top, 5 s samples):" | tee -a $$out; \
	python3 deploy/bench/sample-top.py --summarise $$out.top.tsv | tee -a $$out; echo "==> saved $$out"
endef

bench-traffic:
	$(call bench_run,-t fortio -c $(BENCH_LADDER) -q 0 -d $(BENCH_DURATION),traffic)

bench-latency:
	$(call bench_run,-t fortio -c $(BENCH_LATENCY_CONNS) -q $(BENCH_QPS) -d 30,latency)

# Payload ladder against the fortio echo backend (`/echo`), driven by fortio
# itself rather than benchtool: benchtool cannot raise fortio's 128 KiB response
# buffer, and above it the fast client closes every connection and runs the
# client out of ports. Response bodies of BENCH_SIZES bytes (download), POST
# bodies of the same sizes echoed back (upload), the download ladder over the
# HTTPS listener (self-signed cert, verification off) and over HTTP/2 (h2c).
# BENCH_PAYLOAD_CONNS connections, unlimited QPS, BENCH_DURATION s per rung.
BENCH_SIZES ?= 1024,16384,131072,1048576
BENCH_PAYLOAD_CONNS ?= 64
FORTIO_IMAGE ?= fortio/fortio:1.69.5
bench-download:
	$(call bench_fortio,download,http,/echo?size=SIZE,)
bench-upload:
	$(call bench_fortio,upload,http,/echo,-payload-size SIZE)
bench-https:
	$(call bench_fortio,https,https,/echo?size=SIZE,-k)
bench-h2:
	$(call bench_fortio,h2,http,/echo?size=SIZE,-h2)

# $(1) result name, $(2) scheme, $(3) path, $(4) extra fortio flags; SIZE in
# the path or flags is replaced by each BENCH_SIZES value. One fortio pod per
# rung, output appended to one result file per run with a kubectl top summary.
define bench_fortio
	@mkdir -p $(BENCH_RESULTS); out=$(BENCH_RESULTS)/$$(date +%Y%m%d-%H%M%S)-$(1)-$$(echo "$(GATEWAYS)" | tr ' /' '_-').txt; \
	echo "# fortio load -c $(BENCH_PAYLOAD_CONNS) -qps 0 -t $(BENCH_DURATION)s -httpbufferkb 2048 -nocatchup -uniform $(4) $(2)://<gateway>$(3) sizes=$(BENCH_SIZES)" | tee $$out; \
	KUBECTL="$(MISE) kubectl" python3 deploy/bench/sample-top.py $$out.top.tsv 5 & sampler=$$!; \
	for gw in $(GATEWAYS); do ns=$${gw%/*}; name=$${gw#*/}; \
	  addr=$$($(MISE) kubectl get gateway -n $$ns $$name -o jsonpath='{.status.addresses[0].value}'); \
	  [ -n "$$addr" ] || { echo "$$gw has no address"; exit 1; }; \
	  for size in $$(echo "$(BENCH_SIZES)" | tr ',' ' '); do \
	    path=$$(echo "$(3)" | sed "s/SIZE/$$size/"); extra=$$(echo "$(4)" | sed "s/SIZE/$$size/"); \
	    echo "==> $$name size=$$size $(2)://$$addr$$path $$extra" | tee -a $$out; \
	    $(MISE) kubectl delete pod fortio -n bench --ignore-not-found --wait=true >/dev/null 2>&1; \
	    $(MISE) kubectl run fortio -n bench --restart=Never --image=$(FORTIO_IMAGE) --overrides='{"spec":{"containers":[{"name":"fortio","image":"$(FORTIO_IMAGE)","args":["load","-quiet","-c","$(BENCH_PAYLOAD_CONNS)","-qps","0","-t","$(BENCH_DURATION)s","-httpbufferkb","2048","-nocatchup","-uniform"'"$$(for f in $$extra; do printf ',"%s"' "$$f"; done)"',"'"$(2)://$$addr$$path"'"],"resources":{"requests":{"cpu":"2","memory":"256Mi"}}}]}}' >/dev/null; \
	    $(MISE) kubectl wait pod/fortio -n bench --for=jsonpath='{.status.phase}'=Succeeded --timeout=$$(( $(BENCH_DURATION) + 90 ))s >/dev/null 2>&1 || echo "fortio pod did not finish" | tee -a $$out; \
	    $(MISE) kubectl logs fortio -n bench 2>&1 | grep -E 'target 50%|target 90%|target 99%|All done|Sockets used|Code |Aborting|error' | tee -a $$out; \
	  done; done; \
	$(MISE) kubectl delete pod fortio -n bench --ignore-not-found --wait=false >/dev/null 2>&1; \
	kill $$sampler 2>/dev/null; wait $$sampler 2>/dev/null; \
	echo "==> resource usage while running (kubectl top, 5 s samples):" | tee -a $$out; \
	python3 deploy/bench/sample-top.py --summarise $$out.top.tsv | tee -a $$out; echo "==> saved $$out"
endef

# ── gateway-api-bench control-plane / availability tests (in-cluster tools Job) ─
# Tools from howardjohn/gateway-api-bench built into $(BENCH_TOOLS_IMAGE); each
# target runs one tool against GATEWAYS (space-separated ns/name) and samples
# kubectl top while it runs. Results land in $(BENCH_RESULTS).
BENCH_TOOLS_IMAGE ?= portus/bench-tools:dev
# Extra flags for every tool, e.g. `--log_output_level default:debug` to get
# per-request status codes out of backend-failover (it otherwise only reports
# to VictoriaLogs).
BENCH_TOOL_FLAGS  ?=
BENCH_ROUTES      ?= 100
BENCH_ITERATIONS  ?= 10
BENCH_SCALE_NAMESPACES ?= 10
BENCH_SCALE_ROUTES     ?= 100
BENCH_SCALE_SECONDS    ?= 300

bench-tools-image: disk-check
	docker build -t $(BENCH_TOOLS_IMAGE) -f deploy/bench/Dockerfile.tools .
	$(MISE) k3d image import $(BENCH_TOOLS_IMAGE) -c $(K3D_CLUSTER)

# $(1) = tool command line (space separated), $(2) = result name.
define bench_tool
	@gws=$$(echo "$(GATEWAYS)" | tr ' ' ','); \
	$(MISE) kubectl delete job bench-tools -n bench --ignore-not-found --wait=true >/dev/null 2>&1; \
	BENCH_TOOLS_IMAGE=$(BENCH_TOOLS_IMAGE) BENCH_ARGS="$(1) --gateways=$$gws $(BENCH_TOOL_FLAGS)" python3 deploy/bench/render-job.py tools-job.yaml | $(MISE) kubectl apply -f - >/dev/null; \
	for i in $$(seq 1 60); do phase=$$($(MISE) kubectl get pod -l app.kubernetes.io/name=bench-tools -n bench -o jsonpath='{.items[0].status.phase}' 2>/dev/null); \
	  [ "$$phase" = "Running" ] || [ "$$phase" = "Succeeded" ] || [ "$$phase" = "Failed" ] && break; sleep 1; done; \
	mkdir -p $(BENCH_RESULTS); out=$(BENCH_RESULTS)/$$(date +%Y%m%d-%H%M%S)-$(2)-$$(echo "$(GATEWAYS)" | tr ' /' '_-').txt; \
	KUBECTL="$(MISE) kubectl" python3 deploy/bench/sample-top.py $$out.top.tsv 5 & sampler=$$!; \
	$(MISE) kubectl logs -f job/bench-tools -n bench | tee $$out; \
	kill $$sampler 2>/dev/null; wait $$sampler 2>/dev/null; \
	echo "==> resource usage while running (kubectl top, 5 s samples):" | tee -a $$out; \
	python3 deploy/bench/sample-top.py --summarise $$out.top.tsv | tee -a $$out; echo "==> saved $$out"
endef

# attachedRoutes status latency: creates BENCH_ROUTES HTTPRoutes and times the
# Gateway's listener attachedRoutes counter up and back down.
bench-attached-routes:
	@for gw in $(GATEWAYS); do ns=$${gw%/*}; name=$${gw#*/}; \
	  for i in $$(seq 1 30); do n=$$($(MISE) kubectl get gateway -n $$ns $$name -o jsonpath='{.status.listeners[0].attachedRoutes}'); \
	    [ "$$n" = "0" ] && break; [ $$i = 30 ] && { echo "$$gw still reports $$n attached routes; delete them first"; exit 1; }; sleep 1; done; done
	$(call bench_tool,attachedroutes --routes=$(BENCH_ROUTES),attached-routes)

# Route propagation: applies BENCH_ROUTES routes one by one and measures the
# time until each answers 200 through the Gateway.
bench-probe:
	$(call bench_tool,probe --routes=$(BENCH_ROUTES),probe)

# Route change availability: continuous traffic while the route flips between
# two backends BENCH_ITERATIONS times; any non-200 fails the run. The failover
# test leaves single-port pods labelled app=backend in `default`; the `backend`
# Service here would select them and the flip to port 8081 would be refused, so
# they are removed first.
bench-route-change:
	$(MISE) kubectl delete deploy/backend-healthy pod/backend-unhealthy -n default --ignore-not-found --wait=true
	$(call bench_tool,routechange --iterations=$(BENCH_ITERATIONS),route-change)

# Backend failover: traffic while one of four backend pods is blackholed
# (iptables) and restored, five cycles.
bench-backend-failover:
	$(MISE) kubectl get crd destinationrules.networking.istio.io >/dev/null 2>&1 || $(MISE) kubectl apply -f deploy/bench/stub-crds.yaml
	$(MISE) kubectl get ns envoy >/dev/null 2>&1 || $(MISE) kubectl create ns envoy
	$(call bench_tool,backendfailover,backend-failover)

# Route scale (pilot-load cluster simulation) for BENCH_SCALE_SECONDS while
# sampling control-plane and data-plane resources. The config and a runner
# script are shipped to the Job through the `route-scale` ConfigMap.
bench-route-scale:
	@gws_json=$$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1].split()))' "$(GATEWAYS)"); \
	NAMESPACES=$(BENCH_SCALE_NAMESPACES) ROUTES=$(BENCH_SCALE_ROUTES) GATEWAYS_JSON="$$gws_json" \
	  python3 -c 'import os,sys; t=open("deploy/bench/route-scale.yaml").read(); [t:=t.replace("$${%s}"%k, os.environ[k]) for k in ("NAMESPACES","ROUTES","GATEWAYS_JSON")]; open("/tmp/route-scale.yaml","w").write(t)'; \
	printf 'timeout %s pilot-load cluster --config /work/config/config.yaml 2>&1; echo "pilot-load exit=$$?"\n' $(BENCH_SCALE_SECONDS) > /tmp/route-scale.sh; \
	$(MISE) kubectl create configmap route-scale -n bench --from-file=config.yaml=/tmp/route-scale.yaml --from-file=run.sh=/tmp/route-scale.sh --dry-run=client -o yaml | $(MISE) kubectl apply -f - >/dev/null
	$(call bench_tool,sh /work/config/run.sh,route-scale)

bench-teardown:
	-$(MISE) kubectl delete -f deploy/bench/portus.yaml -f deploy/bench/agentgateway.yaml -f deploy/bench/envoy-gateway.yaml -f deploy/bench/nginx.yaml --ignore-not-found
	-$(MISE) helm uninstall agentgateway agentgateway-crds -n agentgateway-system --wait 2>/dev/null
	-$(MISE) helm uninstall eg -n envoy-gateway-system --wait 2>/dev/null
	-$(MISE) helm uninstall nginx -n nginx-system --wait 2>/dev/null
	-$(MISE) kubectl delete namespace agentgateway-system envoy-gateway-system nginx-system --ignore-not-found
	-$(MISE) kubectl delete -f deploy/bench/backend.yaml -f deploy/bench/echo-backend.yaml --ignore-not-found
	$(MISE) helm upgrade $(HELM_RELEASE) $(HELM_CHART) -n $(NAMESPACE) --reuse-values \
		--set dataplane.replicasPerGateway=1 --set dataplane.resources.requests.cpu=250m --wait

# ── Clean ──────────────────────────────────────────────────────────────────────

clean: k3d-down

# ── Conformance (in-cluster) ─────────────────────────────────────────────────
# The Gateway API suite runs from inside the cluster: Gateway addresses are the
# per-Gateway Services' ClusterIPs, which only pods can reach. Usage:
#   make conformance-image           # build + import the runner image
#   make conformance-run             # all profiles (HTTP, GRPC, TLS, TCP, UDP); report -> tests/conformance/conformance-report.yaml
#   make conformance-run CONFORMANCE_RUN='TestConformance/HTTPRouteMultipleGateways$$'
CONFORMANCE_TAG   ?= dev
CONFORMANCE_IMAGE := portus/conformance:$(CONFORMANCE_TAG)
CONFORMANCE_RUN   ?= TestConformance
CONFORMANCE_TIMEOUT ?= 40m

conformance-image: disk-check
	docker build -t $(CONFORMANCE_IMAGE) -f deploy/conformance/Dockerfile.runner .
	$(MISE) k3d image import $(CONFORMANCE_IMAGE) -c $(K3D_CLUSTER)

conformance-run:
	-$(MISE) kubectl delete job conformance -n portus-conformance --ignore-not-found --wait=true >/dev/null 2>&1
	@# A previous run's cleanup may still be terminating the suite namespaces; a new run cannot create into them.
	@for ns in gateway-conformance-infra gateway-conformance-app-backend gateway-conformance-web-backend gateway-conformance-mesh; do \
		$(MISE) kubectl wait --for=delete ns/$$ns --timeout=180s >/dev/null 2>&1 || true; done
	CONFORMANCE_IMAGE=$(CONFORMANCE_IMAGE) CONFORMANCE_RUN='$(CONFORMANCE_RUN)' CONFORMANCE_TIMEOUT=$(CONFORMANCE_TIMEOUT) \
		python3 deploy/conformance/render-job.py | $(MISE) kubectl apply -f -
	@echo "==> waiting for the conformance pod"
	@for i in $$(seq 1 60); do \
		phase=$$($(MISE) kubectl get pod -l app.kubernetes.io/name=portus-conformance -n portus-conformance -o jsonpath='{.items[0].status.phase}' 2>/dev/null); \
		case "$$phase" in Running|Succeeded|Failed) break;; esac; sleep 3; done
	$(MISE) kubectl logs -f job/conformance -n portus-conformance | tee /tmp/conformance-incluster.txt
	@python3 deploy/conformance/extract-report.py /tmp/conformance-incluster.txt tests/conformance/conformance-report.yaml

conformance-clean:
	-$(MISE) kubectl delete -f deploy/conformance/job.yaml --ignore-not-found

