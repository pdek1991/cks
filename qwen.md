

## **Introduction from Your Mentor**

Hello. The **CKS exam** is a hands-on, problem-solving challenge. You are not just a test-taker; you are a **first responder**, a **solutions architect**, and a **security engineer** all in one.

My goal is to teach you how to **think like one**.

The labs in this guide are your **proving ground**. Don’t just copy-paste the commands — **understand why** you are running them. The *"Very Hard Challenge Questions"* simulate the complex, multi-layered problems you’ll face in the exam and in real-world production.

Let’s begin.

---

## ✅ Week 1: Foundations & Hardening

---

### **Day 1: Cluster Setup, System Hardening**

**Domains:** Cluster Setup, System Hardening  
**Topics:** `kube-bench`, etcd/API Server hardening (`--tls-private-key`, `--etcd-cafile`), RBAC basics (Roles, RoleBindings)

#### 🔍 Interleaved Learning Notes
Start with the core. The **CIS Kubernetes Benchmark** provides a checklist for securing your cluster. Use `kube-bench` to automate it. Simultaneously, introduce **RBAC** — the foundational security control. Understanding how the API server authenticates and authorizes is critical.

#### 💻 Hands-on Labs
```bash
# Run kube-bench
docker run --rm -it --net host --pid host -v /etc:/etc -v /var/lib:/var/lib aquasec/kube-bench:latest

# Inspect kube-apiserver manifest
cat /etc/kubernetes/manifests/kube-apiserver.yaml | grep -E "(tls-private-key|etcd-cafile)"

# Create Role, ServiceAccount, RoleBinding
kubectl create role pod-reader --verb=get,list --resource=pods --namespace=default
kubectl create serviceaccount my-sa --namespace=default
kubectl create rolebinding read-pods --role=pod-reader --serviceaccount=default:my-sa

# Test permissions
kubectl auth can-i get pods --as system:serviceaccount:default:my-sa
```

#### 🧠 Active Recall Questions
- What is the purpose of the CIS Kubernetes Benchmark?
- How would you secure the etcd endpoint?
- Explain the difference between a Role and a ClusterRole.

#### 🔥 Very Hard Challenge Question
> A new developer needs access to view logs across all namespaces. Design and implement the RBAC resources (ClusterRole, ClusterRoleBinding, and ServiceAccount) to grant this access with the principle of least privilege. Explain why a Role is insufficient.

---

### **Day 2: Minimize Microservice Vulnerabilities, Supply Chain Security**

**Domains:** Minimize Microservice Vulnerabilities, Supply Chain Security  
**Topics:** Pod Security Contexts (`runAsNonRoot`, `readOnlyRootFilesystem`), image scanning with `trivy`

#### 🔍 Interleaved Learning Notes
Security starts at the container level. Use `securityContext` to restrict pod behavior. Introduce **Supply Chain Security** via `trivy` to scan images before deployment.

#### 💻 Hands-on Labs
```yaml
# Secure Pod
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
  - name: nginx
    image: nginx
    securityContext:
      runAsNonRoot: true
      readOnlyRootFilesystem: true
```

```bash
# Try to write to filesystem
kubectl exec -it secure-pod -- touch /test.txt  # Should fail

# Scan images
trivy image nginx:latest
trivy image docker.io/library/httpd:2.4.58
```

#### 🧠 Active Recall Questions
- What is the benefit of `readOnlyRootFilesystem: true`?
- How does `trivy` mitigate supply chain attacks?
- What does `allowPrivilegeEscalation` do?

#### 🔥 Very Hard Challenge Question
> A container needs access to `/var/log/app` on the host. Configure `securityContext` to allow this with least privilege.

---

### **Day 3: Cluster Setup, System Hardening**

**Domains:** Cluster Setup, System Hardening  
**Topics:** Pod Security Admission (PSA), Node Hardening, kubelet hardening (`--authorization-mode`, `--read-only-port`)

#### 🔍 Interleaved Learning Notes
Move from pod to node and cluster level. **PSA** replaces PSPs. Harden `kubelet` — a major attack surface.

#### 💻 Hands-on Labs
```bash
# Enable PSA
kubectl label namespace default pod-security.kubernetes.io/enforce=baseline

# Deploy violating pod (e.g., hostPath) — should fail

# Check kubelet flags
ps aux | grep kubelet | grep -E "authorization-mode|read-only-port"

# Disable SSH on node
sudo systemctl stop ssh && sudo systemctl disable ssh
```

#### 🧠 Active Recall Questions
- What are the three PSA levels? Difference between `enforce` and `audit`?
- Why disable kubelet’s read-only port?
- Risk of privileged pods?

#### 🔥 Very Hard Challenge Question
> Legacy app needs `/dev/shm`. Design a PSA policy to allow this only in one namespace. Explain the risk.

---

### **Day 4: Supply Chain Security, Minimize Microservice Vulnerabilities**

**Domains:** Supply Chain Security, Minimize Microservice Vulnerabilities  
**Topics:** Admission Controllers, OPA/Gatekeeper

#### 🔍 Interleaved Learning Notes
Use **OPA/Gatekeeper** to enforce policy as code. Prevent deployments of non-compliant resources.

#### 💻 Hands-on Labs
```bash
# Install Gatekeeper
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.7/deploy/gatekeeper.yaml

# Create ConstraintTemplate + Constraint to enforce labels
kubectl apply -f label-constraint.yaml

# Try to deploy pod without label — should be rejected
```

#### 🧠 Active Recall Questions
- Difference between Validating and Mutating Admission Webhooks?
- How does Gatekeeper improve over `trivy`?
- Purpose of ConstraintTemplates?

#### 🔥 Very Hard Challenge Question
> All images must come from `my.registry.com`. Write a Gatekeeper policy to block external registry pulls.

---

### **Day 5: System Hardening, Cluster Setup**

**Domains:** System Hardening, Cluster Setup  
**Topics:** AppArmor, Seccomp, NetworkPolicy

#### 🔍 Interleaved Learning Notes
Kernel-level controls: AppArmor (file access), Seccomp (syscalls). NetworkPolicy enables **micro-segmentation**.

#### 💻 Hands-on Labs
```yaml
# Pod with AppArmor/Seccomp
securityContext:
  appArmor:
    localhost/profiles/secure-profile
  seccompProfile:
    type: RuntimeDefault
```

```bash
# Load AppArmor profile
sudo apparmor_parser /etc/apparmor.d/secure-profile

# NetworkPolicy: allow only db traffic from web
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-db-from-web
spec:
  podSelector:
    matchLabels:
      app: db
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: web
    ports:
    - protocol: TCP
      port: 3306
```

#### 🧠 Active Recall Questions
- Explain the difference between AppArmor and Seccomp.
- What is the benefit of `seccompProfile: unconfined`? (Trick question!)
- How does NetworkPolicy prevent lateral movement?

#### 🔥 Very Hard Challenge Question
> An attacker has compromised a pod in the `web` namespace. This pod must talk to a database in `db` on port 3306. Design a NetworkPolicy to allow only this. Explain how it prevents lateral movement.

---

## ✅ Week 2: Runtime & Supply Chain Deep Dives

---

### **Day 6: Supply Chain Security, Runtime Security**

**Domains:** Supply Chain Security, Runtime Security  
**Topics:** Advanced `trivy` (SBOMs), `Falco` for real-time detection

#### 🔍 Interleaved Learning Notes
`trivy fs` scans source code. `trivy image --format spdx-json` generates SBOMs. `Falco` monitors runtime behavior.

#### 💻 Hands-on Labs
```bash
# Scan source code
trivy fs /path/to/repo

# Generate SBOM
trivy image --format spdx-json -o sbom.json myimage:v1

# Install Falco
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco

# Trigger rule
kubectl exec -it pod -- sh -c "echo test > /etc/passwd"
```

#### 🧠 Active Recall Questions
- What is a Software Bill of Materials (SBOM)?
- How is Falco different from admission controllers?
- What kernel tech does Falco use?

#### 🔥 Very Hard Challenge Question
> An attacker runs `nmap` from a pod. Write a custom Falco rule to detect this. What syscalls would you monitor?

---

### **Day 7: Cluster Setup, System Hardening**

**Domains:** Cluster Setup, System Hardening  
**Topics:** Advanced RBAC, Certificate Signing Requests (CSRs)

#### 🔍 Interleaved Learning Notes
Understand `system:masters`, `system:nodes`. Manual CSR flow teaches certificate lifecycle.

#### 💻 Hands-on Labs
```bash
# List masters
kubectl get clusterrolebindings -o wide | grep system:masters

# Create CSR for user "bob"
openssl genrsa -out bob.key 2048
openssl req -new -key bob.key -out bob.csr -subj "/CN=bob/O=devs"

# Submit CSR
cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: bob-csr
spec:
  request: $(cat bob.csr | base64 -w0)
  signerName: kubernetes.io/kube-apiserver-client
  usages: ["client auth"]
EOF

# Approve and fetch cert
kubectl certificate approve bob-csr
kubectl get csr bob-csr -o jsonpath='{.status.certificate}' | base64 -d > bob.crt
```

#### 🧠 Active Recall Questions
- What is the purpose of `system:masters`?
- How to grant group access without individual bindings?
- When use CSR vs ServiceAccount?

#### 🔥 Very Hard Challenge Question
> An attacker obtained a ServiceAccount token. Design an RBAC strategy to revoke all access for this SA across all namespaces without affecting others.

---

### **Day 8: Minimize Microservice Vulnerabilities, Supply Chain Security**

**Domains:** Minimize Microservice Vulnerabilities, Supply Chain Security  
**Topics:** Kyverno vs OPA/Gatekeeper, advanced NetworkPolicy

#### 🔍 Interleaved Learning Notes
**Kyverno** is simpler and more Kubernetes-native. Use for policies like image registry enforcement.

#### 💻 Hands-on Labs
```bash
# Install Kyverno
helm install kyverno kyverno/kyverno -n kyverno --create-namespace

# Policy: allow hostPath only in storage-consumers
kubectl apply -f kyverno-hostpath-policy.yaml
```

#### 🧠 Active Recall Questions
- Advantages of Kyverno over Gatekeeper?
- Purpose of Egress in NetworkPolicy?
- When use `namespaceSelector`?

#### 🔥 Very Hard Challenge Question
> A team needs pods to access `/shared/nfs` via `hostPath`. Design a **Kyverno policy** to allow this only in the `storage-consumers` namespace.

---

### **Day 9: Runtime Security, Monitoring & Logging**

**Domains:** Runtime Security, Monitoring & Logging  
**Topics:** Advanced Falco rules, Kubernetes Audit Logs

#### 🔍 Interleaved Learning Notes
Custom Falco rules catch advanced threats. Audit Logs record all API activity.

#### 💻 Hands-on Labs
```yaml
# Custom Falco rule
- rule: Detect Delete in Production
  desc: "Detect kubectl delete in production namespace"
  condition: >
    k8s.ns.name = production and
    ka.verb = delete and
    ka.target.resource = pods
  output: "Delete attempt in production (user=%ka.user.name pod=%ka.target.name)"
  priority: WARNING
```

```bash
# Enable audit logs in kube-apiserver
--audit-log-path=/var/log/audit.log --audit-policy-file=/etc/kubernetes/audit-policy.yaml
```

#### 🧠 Active Recall Questions
- What info is in a Kubernetes Audit Log entry?
- How to configure `auditd` on the host?
- Difference between Falco and SIEM?

#### 🔥 Very Hard Challenge Question
> A malicious actor tried to create a `ClusterRoleBinding` with `system:masters`. Using only **Audit Logs**, describe how to identify the user, timestamp, and full operation details.

---

### **Day 10: System Hardening, Minimize Microservice Vulnerabilities**

**Domains:** System Hardening, Minimize Microservice Vulnerabilities  
**Topics:** `kube-bench` remediation, `gVisor` sandboxing

#### 🔍 Interleaved Learning Notes
Fix `kube-bench` findings. Use `gVisor` for strong container isolation.

#### 💻 Hands-on Labs
```bash
# Fix kube-bench findings
sudo sed -i 's/--read-only-port=[0-9]\+/--read-only-port=0/' /var/lib/kubelet/kubeadm-flags.env

# Install gVisor
curl -s https://storage.googleapis.com/gvisor/releases/release/latest | xargs -I {} curl -fsSLO {}/runsc
sudo mv runsc /usr/local/bin/ && sudo chmod a+x /usr/local/bin/runsc

# Deploy pod with runtimeClassName: gvisor
```

#### 🧠 Active Recall Questions
- How to automate `kube-bench` remediation?
- What is a container sandbox? How does `gVisor` work?
- What performance trade-off does `gVisor` introduce?

#### 🔥 Very Hard Challenge Question
> A developer needs to run an untrusted container. Design a solution using **gVisor** and **NetworkPolicy** to isolate it. Describe the security benefits.

---

## ✅ Week 3: Advanced Architecting & Tool Integration

---

### **Day 11: Runtime Security, Cluster Setup**

**Domains:** Runtime Security, Cluster Setup  
**Topics:** `kubectl-debug`, ServiceAccount token security

#### 🔍 Interleaved Learning Notes
`kubectl-debug` is essential for incident investigation. Understand token mounting and lifecycle.

#### 💻 Hands-on Labs
```bash
# Install kubectl-debug
wget https://github.com/aylei/kubectl-debug/releases/download/v1.0.4/kubectl-debug_1.0.4_linux_amd64.tar.gz
tar -xzf kubectl-debug_*.tar.gz && sudo mv kubectl-debug /usr/local/bin/

# Debug a pod
kubectl debug -it <pod-name> --image=nicolaka/netshoot

# Disable token auto-mount
automountServiceAccountToken: false
```

#### 🧠 Active Recall Questions
- When use `kubectl-debug` instead of `exec`?
- Risk of token exfiltration?
- How to disable automatic token mount?

#### 🔥 Very Hard Challenge Question
> An investigation is underway on a compromised pod. Using `kubectl-debug`, describe how to:  
> 1) Inspect running processes  
> 2) Check mounted token and permissions  
> 3) Review recent file changes  
> ...without stopping the container.

---

### **Day 12: Monitoring & Logging, Runtime Security**

**Domains:** Monitoring & Logging, Runtime Security  
**Topics:** `auditd`, `kube-bench node`, host-level auditing

#### 🔍 Interleaved Learning Notes
Nodes are attack surfaces. Use `auditd` to monitor host changes. `kube-bench node` checks worker node hardening.

#### 💻 Hands-on Labs
```bash
# Install auditd
sudo apt install auditd

# Monitor critical files
sudo auditctl -w /etc/docker -p wa -k docker-change
sudo auditctl -w /var/lib/kubelet -p wa -k kubelet-change

# Run kube-bench on node
docker run --rm -v /etc:/etc -v /var:/var aquasec/kube-bench:latest master --targets=node
```

#### 🧠 Active Recall Questions
- How is `auditd` different from Kubernetes Audit Logs?
- Key security recommendations for worker nodes?
- Purpose of `kube-bench node` vs `master`?

#### 🔥 Very Hard Challenge Question
> `auditd` shows a user modified a file in `/var/lib/kubelet`. What log entries would you check? What `kubectl` commands would you run to correlate with cluster activity?

---

### **Day 13: Supply Chain Security**

**Domains:** Supply Chain Security, Minimize Microservice Vulnerabilities  
**Topics:** Image Signing (Sigstore/cosign), admission verification

#### 🔍 Interleaved Learning Notes
Signing ensures **authenticity and integrity**. Use admission controllers to enforce signature checks.

#### 💻 Hands-on Labs
```bash
# Sign image with cosign
cosign sign --key cosign.key my.registry.com/myimage:v1

# Verify in Kyverno or Gatekeeper
# Policy checks signature before admission
```

#### 🧠 Active Recall Questions
- Difference between image integrity and authenticity?
- Why is Sigstore better than a hash?
- Three main components of Sigstore?

#### 🔥 Very Hard Challenge Question
> Corporate policy requires **dual signatures** (builder + security). Design an admission policy to enforce this.

---

### **Day 14: Cluster Setup, Monitoring & Logging**

**Domains:** Cluster Setup, Monitoring & Logging  
**Topics:** TLS for Ingress/Egress, control plane hardening, Falco to syslog

#### 🔍 Interleaved Learning Notes
Secure communication with TLS. Harden `scheduler` and `controller-manager`. Send Falco alerts to SIEM.

#### 💻 Hands-on Labs
```yaml
# Ingress with TLS
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secure-ingress
spec:
  tls:
  - hosts:
    - app.example.com
    secretName: tls-secret
```

```bash
# Configure Falco output to syslog
# In falco.yaml: output_format: syslog
```

#### 🧠 Active Recall Questions
- Security benefit of TLS on Ingress?
- Why secure `kube-controller-manager`?
- Why not rely on local Falco output?

#### 🔥 Very Hard Challenge Question
> An attacker on a worker node tries to spoof API calls to `kube-scheduler`. Describe scheduler security configs that prevent this, and what Falco/Audit Log events you’d look for.

---

### **Day 15: Mid-point Review & Integration**

**Domains:** All Domains  
**Topics:** Review, integration of concepts

#### 💻 Hands-on Labs
- Re-run `kube-bench`
- Use `kubectl-debug` to verify `seccomp`/`AppArmor`
- Review all NetworkPolicy and Falco rules

#### 🧠 Active Recall Questions
- Summarize how NetworkPolicy, Falco, and OPA work together.
- Explain "least privilege" in RBAC and Pod Security.
- Biggest gap if you only use `trivy`?

#### 🔥 Very Hard Challenge Question
> A new microservice needs:
> - Privileged access to `/proc`
> - External API access
> - Image from non-approved registry  
> Design a **multi-layered security plan** using OPA, NetworkPolicy, gVisor, and AppArmor.

---

## ✅ Week 4: Exam Simulation & Final Review

---

### **Day 16–20: Full-Scale Mock Exams**

**Domains:** All  
**Topics:** Timed drills, mock exams

#### 💻 Hands-on Labs
- Complete one full CKS mock exam per day
- 30-minute drill: write a complex NetworkPolicy from memory

#### 🔥 Very Hard Challenge Questions
> **Scenario 1**: Falco alerts on shell in root container. You must:  
> 1) Identify misconfigured pod  
> 2) Investigate with `kubectl-debug`  
> 3) Write a Kyverno policy to prevent recurrence  

> **Scenario 2**: Attacker has SA token and tries to pivot. You must:  
> 1) Check SA permissions  
> 2) Audit API calls (success/failure)  
> 3) Revoke token and access

---

### **Day 21–25: Advanced Review**

**Domains:** All  
**Topics:** Weak spot refinement

#### 💻 Hands-on Labs
- Debug complex NetworkPolicies with multiple selectors
- Write and test a Falco rule from scratch
- Fix all remaining `kube-bench` findings

#### 🔥 Very Hard Challenge Questions
> **Scenario 1**: Falco alert lacks context. Describe how to integrate `auditd` logs for a complete event picture.  
> **Scenario 2**: Write a NetworkPolicy allowing inbound traffic only from pods with label `role: frontend`, but only if they are in a namespace labeled `team: security`.

---

### **Day 26–30: Final Review & Mental Prep**

**Domains:** All  
**Topics:** Final prep, exam mindset

#### 💻 Hands-on Labs
- Complete 2–3 final mock exams
- Day 29: Rest
- Day 30: Review official CKS docs and tool list

#### 🔥 Final Very Hard Challenge Question
> **Final Scenario**: Your production cluster is under attack.  
> - Falco reports `port_scan_detected` from a pod in `staging`  
> - Audit Logs show failed attempts to delete `clusterroles`  
> Provide a **step-by-step plan** for **containment, investigation, and remediation** using all tools and knowledge from the last 30 days.

---

# ✅ Comprehensive Kubernetes Security & Architecture Checklist  
*(Printable - Designed for 10+ Years of Production Experience Level)*

Use this checklist to validate mastery across **on-prem**, **cloud**, and **hybrid** environments. Ensure you can **architect**, **deploy**, **secure**, and **troubleshoot** any microservices + DB application.

---

## 🔐 **Cluster Security & Hardening**
- [ ] CIS Benchmark compliance via `kube-bench`
- [ ] etcd encrypted at rest and TLS-enabled
- [ ] API Server hardened: `--tls-cert-file`, `--client-ca-file`, `--anonymous-auth=false`
- [ ] kubelet: `--authorization-mode=Webhook`, `--read-only-port=0`
- [ ] Control plane components (scheduler, controller-manager) use secure flags
- [ ] SSH disabled on nodes; access via bastion/jump host
- [ ] Audit Logs enabled with policy for `RequestResponse` level

## 🛡️ **Pod & Container Security**
- [ ] All pods run as non-root (`runAsNonRoot: true`)
- [ ] `readOnlyRootFilesystem: true` enforced
- [ ] `allowPrivilegeEscalation: false`
- [ ] AppArmor profiles loaded and enforced
- [ ] Seccomp profiles applied (`RuntimeDefault` or custom)
- [ ] gVisor or Kata Containers used for untrusted workloads
- [ ] Privileged pods banned via PSA or OPA

## 🔐 **Identity & Access Management (IAM)**
- [ ] Minimal `system:masters` access; rotated regularly
- [ ] RBAC: Least privilege roles, no wildcards
- [ ] ServiceAccount tokens not auto-mounted unless required
- [ ] Short-lived tokens or workload identity (e.g., Kubelet CSR rotation)
- [ ] Certificate Signing Requests (CSRs) manually approved for users
- [ ] OIDC integration for external identity providers

## 🧱 **Policy as Code & Admission Control**
- [ ] OPA/Gatekeeper or Kyverno installed and enforced
- [ ] Policies: image registry allowlist, required labels, hostPath restrictions
- [ ] Pod Security Admission (PSA) enforced at `restricted` level in prod
- [ ] Mutating policies for default security context
- [ ] Image signing enforced via cosign + admission controller

## 🧩 **Supply Chain Security**
- [ ] `trivy` integrated into CI/CD for image and IaC scanning
- [ ] SBOMs generated and stored for every image
- [ ] Image signing with Sigstore (cosign)
- [ ] Private registry with image vulnerability scanning
- [ ] Air-gapped clusters use mirrored, scanned images

## 🌐 **Network Security**
- [ ] CNI plugin supports NetworkPolicy (Calico, Cilium)
- [ ] Default-deny NetworkPolicy in all namespaces
- [ ] Micro-segmentation: only required pod-to-pod traffic allowed
- [ ] Egress policies restrict outbound traffic (e.g., block internet)
- [ ] Ingress with TLS termination and WAF integration
- [ ] Service Mesh (Istio/Linkerd) for mTLS in production

## 🚨 **Runtime & Threat Detection**
- [ ] Falco installed with custom rules
- [ ] Rules: shell in container, file changes, privilege escalation
- [ ] Falco alerts sent to SIEM (Splunk, ELK, Datadog)
- [ ] `auditd` on nodes to monitor `/etc`, `/var/lib/kubelet`
- [ ] Correlation between Falco alerts and Kubernetes Audit Logs

## 🛠️ **Operational Tooling Mastery**
- [ ] `kubectl-debug` installed and used for forensics
- [ ] `kubectl auth can-i` used to test RBAC
- [ ] `trivy` used for image, fs, and config scanning
- [ ] `kube-bench` run regularly on master and nodes
- [ ] Proficient with `vim`, `grep`, `sed`, `journalctl`, `systemctl`

## 🏗️ **Architecture & Production Readiness**
- [ ] Can design multi-tenant cluster with namespace quotas, network isolation
- [ ] Can deploy microservices with DB (PostgreSQL/MySQL) securely
- [ ] Can configure backup/restore (Velero) and disaster recovery
- [ ] Can set up monitoring (Prometheus, Grafana) and logging (Fluentd, Loki)
- [ ] Can secure on-prem and cloud (EKS/GKE/AKS) clusters
- [ ] Can troubleshoot RBAC, PSA, NetworkPolicy, and admission issues

## ✅ **Final Validation**
- [ ] Completed 5+ full CKS mock exams with >90% score
- [ ] Solved all "Very Hard Challenge Questions" without hints
- [ ] Can explain every security control in production terms
- [ ] Ready to architect and secure any Kubernetes workload from Day 1

---

> ✅ **Tip:** Print this checklist. Tick each box after hands-on lab. Review weekly.  
> You're not just passing CKS — you're becoming a **Kubernetes Security Architect**.

**Now go secure the cluster.** 🔐
```