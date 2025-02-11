🛡️ Kubernetes Security - CKS Preparation (KodeCloud)
📌 Security Tools & Best Practices for Kubernetes
🔍 Kubernetes Security Benchmarking
📌 Kube-Bench (CIS Kubernetes Benchmark)
Kube-Bench checks Kubernetes clusters against CIS security benchmarks.

bash
Copy
Edit
# Download and run kube-bench
curl -L -o kube-bench.tar.gz https://github.com/aquasecurity/kube-bench/releases/download/v0.4.0/kube-bench_0.4.0_linux_amd64.tar.gz
tar -xvf kube-bench.tar.gz
./kube-bench --config-dir `pwd`/cfg --config `pwd`/cfg/config.yaml
🔐 TLS & mTLS in Kubernetes
📌 TLS Handshake (RSA-based)
ClientHello → Sends supported cipher suites, TLS versions, and a random value.
ServerHello → Responds with the chosen cipher suite and a random value.
Server Certificate → Sent to the client (contains public key, domain, CA signature).
Certificate Validation → Client validates the server certificate.
Key Exchange → Client generates and encrypts a pre-master secret using the server’s public key.
Server Decrypts & Derives Session Key → Using the private key.
Secure Communication Begins → Both client and server use the session key.
📌 Mutual TLS (mTLS) - Additional Steps
🔹 Both client & server authenticate using certificates.
🔹 Session key is established after mutual authentication.
🔹 Used in Istio, Linkerd, and Zero Trust Networks.
pgsql
Copy
Edit
|------------------------------------------------------|
| Client                                       Server  |
|  | ------- ClientHello ------------------>  |       |
|  | <------ ServerHello, ServerCert -------- |       |
|  | ------- ClientCert, KeyExchange -------> |       |
|  | <------ KeyExchange, Finished ---------- |       |
|  | ------- Finished ----------------------> |       |
|  | ==== Secure Encrypted Communication ==== |       |
|------------------------------------------------------|
🛡️ System Hardening for Kubernetes
📌 Secure the Host & Cluster
✅ Limit access to nodes → Disable password-based SSH, root SSH
✅ RBAC Enforcement → Define strict roles & permissions
✅ Remove unused packages/services → Reduce attack surface
✅ Restrict network access → Firewall, namespaces, service policies
✅ Restrict kernel modules → Prevent privilege escalation
✅ Scan for open ports & vulnerabilities

🔑 Secure Docker Host
📌 Enable TLS for Docker
Generate CA & TLS certificates for both client & server.
Enable tlsverify in the Docker config.
Copy client & CA certificates to ~/.docker/ to allow CLI access.
bash
Copy
Edit
# Verify TLS connection
docker --tlsverify -H tcp://remote-docker-host:2376 version
🔍 Kubernetes Security & Compliance Tools
📌 SBOM (Software Bill of Materials)
Syft → Generates SBOMs for container images.
Grype → Scans SBOMs for vulnerabilities.
Trivy → Lightweight image scanner.
Kubescape → Detects misconfigurations & compliance violations.
bash
Copy
Edit
trivy image myapp:v1.0  # Scan an image
🔥 Container Runtime Security
📌 How a Docker Container Starts:
Docker CLI → Converts command to REST API request.
Docker Daemon → Pulls the image from the registry.
Containerd → Converts image to OCI format.
Containerd-shim → Calls container runtime.
RunC → Creates namespaces & cGroups to run the container.
💡 Alternative runtimes:

gVisor (runsc) → Lightweight user-space runtime.
Kata Containers → VM-based lightweight runtime.
bash
Copy
Edit
docker run --runtime=runsc -d nginx
📌 RuntimeClass Configuration:
yaml
Copy
Edit
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor-runtime
handler: runsc
yaml
Copy
Edit
spec:
  runtimeClassName: gvisor-runtime
🔐 Kubernetes Security Categories
1️⃣ Image Scanning & Container Security
Tool	Description
Trivy	Lightweight vulnerability scanner
Anchore	Image policy & security enforcement
Clair	Static vulnerability analysis
Grype	Scans container images for CVEs
Docker Bench	Checks Docker host security
2️⃣ Kubernetes Runtime Security
Tool	Description
Falco	Detects abnormal container behavior
Sysdig Secure	Real-time threat detection
Prisma Cloud	Comprehensive Kubernetes security
NeuVector	Full lifecycle runtime security
3️⃣ Network Security & Policy Enforcement
Tool	Description
Cilium	eBPF-based security & networking
Calico	Network policies & microservice isolation
Istio	Service mesh with built-in mTLS
Linkerd	Lightweight service mesh with TLS
4️⃣ Kubernetes Compliance & Policy Management
Tool	Description
OPA Gatekeeper	Kubernetes policy enforcement
Kyverno	Kubernetes-native policy engine
Kube-Bench	CIS benchmark for Kubernetes security
Kube-Hunter	Security vulnerability scanner
5️⃣ Secrets Management & Encryption
Tool	Description
Sealed Secrets	Encrypts secrets for GitOps
Vault	Secure secret management
AWS Secrets Manager	Cloud-native secret management
SOPS	Encrypts secrets and config files
6️⃣ Kubernetes API Security & RBAC Management
Tool	Description
K-Rail	RBAC policy enforcement
Kubeaudit	Audits RBAC misconfigurations
RBAC Manager	Simplifies RBAC management
Dex	OpenID authentication for Kubernetes
7️⃣ Software Supply Chain Security
Tool	Description
Sigstore	Secure software supply chain signing
TUF	Secure software updates
In-Toto	End-to-end supply chain security
Notary	Container image integrity verification
8️⃣ Observability & Security Forensics
Tool	Description
Kube-Monkey	Chaos engineering for Kubernetes
Tetragon	Real-time security observability
OpenTelemetry	Monitors security-related metrics
Prometheus + Grafana	Security & incident response dashboards
🚀 Additional Kubernetes Security Hardening
🔹 Enable Audit Logging → Capture API requests & user actions.
🔹 Use Pod Security Standards (PSS) → Restrict pod privileges.
🔹 Limit Privilege Escalation → Use securityContext: allowPrivilegeEscalation: false.
🔹 Use Network Policies → Restrict traffic between pods.
