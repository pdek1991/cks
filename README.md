🛡️ Kubernetes Security - CKS Preparation

Kube-Bench tool dwnload link
https://github.com/aquasecurity/kube-bench/releases/download/v0.4.0/kube-bench_0.4.0_linux_amd64.tar.gz

./kube-bench --config-dir `pwd`/cfg --config `pwd`/cfg/config.yaml

===========================XXXXXXXXXXXXXXXXXXXXXXXX============================XXXXXXXXXXXXXXXXXXXXXXXX==================

🔐 TLS & mTLS in Kubernetes
Certificate authority
PKI Public key infrastructure

TLS Handshake with RSA (Securing the Connection)
The browser starts the TLS handshake to establish a secure connection.

Step 4.1: ClientHello
The browser sends a ClientHello message to the server with:
Supported cipher suites (e.g., RSA, AES, ECDHE).
A random value (random1).
Supported TLS versions.

Step 4.2: ServerHello
The server responds with a ServerHello message containing:
The chosen cipher suite.
A random value (random2).

Step 4.3: Server Certificate
The server sends its certificate to the client. This certificate includes:
The server's public key.
Details about the server's identity (domain name).
A digital signature from a trusted Certificate Authority (CA).

Step 4.4: Certificate Validation
The browser validates the server’s certificate:
It checks the CA's signature to verify authenticity.
Ensures the certificate matches the domain name (example.com).
Checks that the certificate is not expired or revoked.

Step 4.5: Key Exchange
Client generates a pre-master secret (a random number used for session key derivation).
The pre-master secret is encrypted with the server's public key (from its certificate) and sent to the server.

Step 4.6: Server Decrypts Pre-Master Secret
The server uses its private key to decrypt the pre-master secret.

Step 4.7: Session Key Derivation
Both the client and server independently compute the session key using:
The pre-master secret.
Random values (random1 and random2).

Step 4.8: Finished Messages
Both the client and server send encrypted Finished messages to confirm that the handshake is complete.
If successful, the secure connection is established.

--------------------

Key Points of mTLS:-
Server Authentication:
The server proves its identity to the client using its certificate.

Client Authentication:
The client proves its identity to the server by presenting its own certificate.

Certificates:
Both client and server certificates are typically signed by a trusted Certificate Authority (CA).
In private systems (e.g., microservices communication), certificates may be issued by an internal CA.

Session Key:
After mutual authentication, a symmetric session key is established for encrypting the communication.


===========================XXXXXXXXXXXXXXXXXXXXXXXX============================XXXXXXXXXXXXXXXXXXXXXXXX==================

Config File
Use tokens to create config 
Map token based secret to user


Secure docker host by creating TLS certs and CA cert for client and server then enable tlsverify in config file
Copy client and CA certs to .docker dir in user home dir to access docker cli

===========================XXXXXXXXXXXXXXXXXXXXXXXX============================XXXXXXXXXXXXXXXXXXXXXXXX==================

🛡️ System Hardening for Kubernetes
	Limit access to nodes
	RBAC Access
	Remove absolute packages and services
	Restrict NW access
	Restrict obsolute Kernel modules
	Identify and Fix open ports

Minimize OS footprint:
  Limit access to nodes:
    Disable password based ssh and root ssh
  Privilage Escallation:

===========================XXXXXXXXXXXXXXXXXXXXXXXX============================XXXXXXXXXXXXXXXXXXXXXXXX==================

OPA:

curl -L -o opa https://github.com/open-policy-agent/opa/releases/download/v0.11.0/opa_linux_amd64

./opa run -s ##run as server



===========================XXXXXXXXXXXXXXXXXXXXXXXX============================XXXXXXXXXXXXXXXXXXXXXXXX==================

🔥 Container Runtime Security:
When we run docker run command
	1. Docker CLI converts command to REST API call
	2. Docker Daemon pulls image from registry
	3. Docker daemon makes call to containerd to start containerd
	4. Containerd converts image to OCI compliant bundle and pass to containerd-shim
	5. Containerd-shim calls container runtime runC 
	6. runC interacts with namespace and cGroups of kernel to start the container
With runC available we can directly run container via CLI	but its difficult to manage its

Other runC available are kata-runtime and Runsc(gVisor)
docker run --runtime=runsc or --runtime=kata -d nginx

Install runtime like runsc and kata and add it in continerd config file  "/etc/containerd/config.toml"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runsc]
   runtime_type = "io.containerd.runsc.v1"

Create runtimeclass object with name and handler
use this in pod defination as runtimeClassName: in .spec to se that runtime to run container

===========================XXXXXXXXXXXXXXXXXXXXXXXX============================XXXXXXXXXXXXXXXXXXXXXXXX==================
📌 Mutual TLS (mTLS) - Additional Steps

Step 1: Client Initiates a TLS Handshake
		The client sends a ClientHello message to the server.
		This message includes:
		The supported TLS versions.
		The cipher suites the client can use.
		A randomly generated number (used for key derivation).
		The hostname of the server (SNI – Server Name Indication).
Step 2: Server Responds with ServerHello
		The server replies with a ServerHello message, which includes:
		The selected TLS version and cipher suite.
		A randomly generated number.
		The server's digital certificate (containing its public key and signed by a trusted CA).
Step 3: Server Certificate Validation
	The client:
		Checks if the server certificate is valid (not expired, issued by a trusted CA).
		Verifies the server's domain name against the certificate.
		Ensures the certificate hasn't been revoked (via CRL or OCSP).
Step 4: Client Certificate Request (mTLS-Specific)
		Unlike normal TLS, in mTLS, the server requests a certificate from the client.
		The server sends a CertificateRequest message to indicate that the client must provide its certificate for authentication.
Step 5: Client Sends Certificate
		The client responds by sending its own certificate, signed by a trusted CA.
		It also proves ownership of the certificate by signing a challenge (using its private key).
Step 6: Server Validates Client Certificate
	The server:
		Verifies if the client certificate is valid (not expired, issued by a trusted CA).
		Ensures the certificate hasn't been revoked.
		Checks the client's identity if needed (e.g., a specific role, user, or service account).
Step 7: Key Exchange and Session Key Generation
		Both the client and server agree on a shared secret key (session key) using:
		Diffie-Hellman (DH) or Elliptic Curve Diffie-Hellman (ECDH).
		The random numbers exchanged in ClientHello/ServerHello are used in key derivation.
Step 8: Secure Encrypted Communication Starts
		Both parties use the session key to encrypt all further communication using symmetric encryption (e.g., AES-GCM).
		A Finished message is sent by both sides to confirm successful authentication and encryption setup.


|------------------------------------------------------|
|Client                                       Server   |
|  | ------- ClientHello ------------------>  |        |
|  | <------ ServerHello, ServerCert -------- |        |
|  | ------- ClientCert, KeyExchange ------->  |       |
|  | <------ KeyExchange, Finished ---------- |        |
|  | ------- Finished ---------------------->  |       |
|  | ==== Secure Encrypted Communication ==== |        |
|------------------------------------------------------|


Istio and Linkerd for mTLS
===========================XXXXXXXXXXXXXXXXXXXXXXXX============================XXXXXXXXXXXXXXXXXXXXXXXX==================

🔍 Kubernetes Security & Compliance Tools
SBOM is detailed inventory of all components, libraries, and dependencies in a software application

SBOM Tools for Kubernetes:
	Syft (by Anchore) 		   → Generates SBOMs for container images.
	Grype (by Anchore) 		   → Works with SBOM to find vulnerabilities.
	Trivy (by Aqua Security)   → Scans container images and generates SBOMs.
	kubescape 				   → Detects misconfigurations, RBAC issues, and compliance violations.
	
kube-linter lint nginx.yml ==> Will provide suggestion for following best practices 

===========================XXXXXXXXXXXXXXXXXXXXXXXX============================XXXXXXXXXXXXXXXXXXXXXXXX==================

🔐 Kubernetes Security Categories

1️⃣ Image Scanning & Container Security
Trivy 						– Lightweight vulnerability scanner for container images, file systems, and Git repositories.
Anchore 					– Open-source image analysis and policy-based security enforcement.
Clair 						– Static analysis of vulnerabilities in container images.
Grype 						– Another vulnerability scanner for container images from Anchore.
Docker Bench for Security 	– Assesses security configurations of Docker hosts and containers.

-------------------------------------------------------------------------------------------------------------------------

 2️⃣ Kubernetes Runtime Security
Detect and prevent runtime security threats in Kubernetes clusters.

Falco 						– Open-source runtime security tool that detects abnormal behavior in containers.
Sysdig Secure 				– Provides real-time runtime threat detection and forensics.
Prisma Cloud (by Palo Alto) – Offers comprehensive cloud security, including Kubernetes runtime protection.
NeuVector 					– Full lifecycle Kubernetes security, including runtime protection.

-------------------------------------------------------------------------------------------------------------------------

3️⃣ Network Security & Policy Enforcement
Secure Kubernetes network traffic using policies and monitoring.

Cilium 		– Provides eBPF-powered security, networking, and observability.
Calico 		– Implements network policies for microservices and workload isolation.
Istio 		– Service mesh with built-in mTLS (mutual TLS) and security policies.
Linkerd 	– Lightweight service mesh with security features like automatic TLS encryption.

-------------------------------------------------------------------------------------------------------------------------

4️⃣ Kubernetes Compliance & Policy Management
Enforce best practices and compliance for Kubernetes configurations.

OPA Gatekeeper 		– Enforces Kubernetes security policies using Open Policy Agent (OPA).
Kyverno 			– Kubernetes-native policy management tool for admission control and compliance.
Kube-bench 			– Checks Kubernetes clusters for security best practices using CIS benchmarks.
Kube-hunter 		– Actively scans Kubernetes clusters for security vulnerabilities.

-------------------------------------------------------------------------------------------------------------------------

5️⃣ Secrets Management & Encryption
Manage Kubernetes secrets securely.

Sealed Secrets (Bitnami) 	– Encrypts Kubernetes secrets to store them safely in Git repositories.
Vault (HashiCorp) 			– Manages and encrypts Kubernetes secrets securely.
AWS Secrets Manager			– Secure secret management for Kubernetes workloads on AWS.
SOPS (Mozilla) 				– Encrypts Kubernetes secrets and configuration files.

-------------------------------------------------------------------------------------------------------------------------

6️⃣ Kubernetes API Security & RBAC Management
Secure Kubernetes API access and RBAC.

K-Rail 			– Kubernetes RBAC policy enforcement and security guardrails.
Kubeaudit 		– Audits Kubernetes clusters for RBAC misconfigurations.
RBAC Manager 	– Helps manage and simplify Kubernetes Role-Based Access Control (RBAC).
Dex 			– Open-source OIDC authentication provider for Kubernetes.

-------------------------------------------------------------------------------------------------------------------------

7️⃣ Software Supply Chain Security
Secure software supply chains in Kubernetes environments.

Sigstore (Cosign, Rekor, Fulcio) 	– Provides signing and verification for container images.
TUF (The Update Framework) 			– Secures software supply chain updates.
in-toto 							– Provides end-to-end supply chain security.
Notary 								– Helps ensure the integrity of container images.

-------------------------------------------------------------------------------------------------------------------------

8️⃣ Observability & Security Forensics
Security visibility and incident response.

Kube-monkey 			– Tests Kubernetes cluster resilience by randomly terminating pods.
Tetragon (Cilium) 		– Real-time Kubernetes security and observability with eBPF.
OpenTelemetry 			– Provides observability for monitoring security-related metrics.
Prometheus + Grafana 	– Collects and visualizes security-related Kubernetes metrics.


