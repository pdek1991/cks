# 🛡️ 30-Day Kubernetes Security Mastery & CKS Exam Prep Guide

By following this plan, you will:  
1. **Pass CKS confidently.**  
2. Reach **senior production-level Kubernetes security expertise (10+ years equivalent).**  
3. Build **practical muscle memory** with daily labs, spaced repetition, and interleaved learning.  

---

# 📅 Study Plan Breakdown

---

## 📅 Day 1 – Cluster Setup + System Hardening Foundations
**Domains:** Cluster Setup, System Hardening  

### Topics
- CKS Exam structure & domains.  
- Securing kube-apiserver: disable anonymous auth, RBAC.  
- Certificates, kubeadm init defaults.  
- Why cluster hardening is critical at enterprise scale.  

### Labs
- Build a kubeadm cluster.  
- Disable anonymous auth in `kube-apiserver.yaml`.  
- Verify:  



### Active Recall
1. Why disable anonymous-auth?  
2. List 3 kube-apiserver flags for hardening.  

### Challenge
- Live cluster API accessible publicly. How do you verify + remediate without downtime?

---

## 📅 Day 2 – RBAC + Namespaces
**Domains:** Cluster Setup, System Hardening  

### Topics
- Roles vs ClusterRoles.  
- RBAC least-privilege.  
- Multi-tenancy with namespaces.  

### Labs
- Create namespace `dev`.  
- Create Role allowing Pods CRUD, but not Secrets.  
- Test via service accounts + impersonation.  

### Active Recall
1. Role vs ClusterRole?  
2. How to check effective permissions of a user?  

### Challenge
- Developers have cluster-role binding with wildcard verbs. How do you migrate to least-privilege with zero downtime?

---

## 📅 Day 3 – Pod Security Admission & Context
**Domains:** System Hardening, Runtime Security  

### Topics
- Pod Security Admission (Baseline, Restricted).  
- Seccomp, AppArmor.  
- OPA/Gatekeeper, Kyverno.  

### Labs
- Enable Restricted PSA for namespace.  
- Deploy privileged Pod → fail.  
- Enforce seccomp via Gatekeeper.  

### Active Recall
1. PSA vs legacy PSP?  
2. Why seccomp important?  

### Challenge
- GPU apps need privileged mode but PSA restricts it. How balance compliance vs business need?

---

## 📅 Day 4 – Network Security  
**Domains:** Cluster Setup, Runtime Security  

### Topics
- CNI (Calico, Cilium).  
- NetworkPolicies: default deny pattern.  

### Labs
- Apply default-deny policy.  
- Explicitly allow DB traffic only from app pods.  
- Test via `kubectl exec curl`.  

### Active Recall
1. NetworkPolicy default if none defined?  
2. Calico vs Cilium: key differences.  

### Challenge
- You must isolate payments namespace but allow Prometheus scrapes. How design rules?

---

## 📅 Day 5 – Supply Chain Security: Image Scanning  
**Domains:** Supply Chain Security, Minimize Microservice Vulnerabilities  

### Topics
- Image CVEs.  
- Scanning: Trivy, Grype.  
- Policy enforcement in CI/CD.  

### Labs
- Run `trivy image nginx:latest`.  
- Create Kyverno rule → block `latest` tags.  

### Active Recall
1. Why avoid `:latest` tags?  
2. Types of image scanner findings?  

### Challenge
- Prod workloads show multiple high CVEs. How handle remediation without downtime?

---

## 📅 Day 6 – Secrets Management  
**Domains:** System Hardening, Minimize Microservice Vulnerabilities  

### Topics
- Kubernetes Secrets: base64 not encryption.  
- Enable at-rest encryption with KMS.  
- Avoid environment variable exposure.  

### Labs
- Enable `EncryptionConfiguration`.  
- Verify secrets not plain-text in etcd.  

### Active Recall
1. How detect if secrets are encrypted?  
2. Why not store TLS keys in ConfigMaps?  

### Challenge  
- You find plaintext passwords in Git. How fix and prevent recurrence?

---

## 📅 Day 7 – Admission Control + OPA & Kyverno  
**Domains:** Cluster Setup, Supply Chain Security, Runtime  

### Topics
- Dynamic Admission Controllers.  
- OPA/Gatekeeper vs Kyverno.  
- Policies at enterprise scale.  

### Labs
- Write Gatekeeper constraint: deny privileged pods.  
- Write Kyverno policy: require specific labels.  

### Active Recall
1. OPA Gatekeeper architecture?  
2. Strength of Kyverno?  

### Challenge
- Organization mandates **signed images**. Implement admission policies to enforce.

---

## 📅 Day 8 – Pod Security Profiles: Seccomp + AppArmor  
**Domains:** System Hardening, Runtime Security  

### Topics
- Seccomp filters syscall abuse.  
- AppArmor profiles for process restriction.  

### Labs
- Apply unconfined vs restricted seccomp profile.  
- Write AppArmor profile around nginx.  

### Active Recall
1. Benefit of seccomp over AppArmor?  
2. Default action if profile missing?  

### Challenge
- Running container exploited kernel CVE via syscalls. How mitigate?

---

## 📅 Day 9 – Runtime Sandboxing (gVisor, Kata)  
**Domains:** Runtime Security  

### Topics
- gVisor, Kata Containers.  
- Pros/cons sandboxing vs performance.  

### Labs
- Deploy workload with gVisor runtime class.  
- Compare performance overhead.  

### Active Recall
1. What is RuntimeClass?  
2. Trade-offs of Kata Containers?  

### Challenge
- Compliance requires isolation between tenants in shared cluster. Sandbox strategy?

---

## 📅 Day 10 – kube-bench + CIS Benchmarking  
**Domains:** System Hardening  

### Topics
- kube-bench.  
- CIS Security Benchmarks.  

### Labs
- Run `kube-bench master` + node.  
- Fix failed checks (audit logging, flags).  

### Active Recall
1. Key kube-bench flags?  
2. How integrate into CI/CD?  

### Challenge
- Prod audits CIS benchmark weekly. How automate with minimal ops?

---

## 📅 Day 11 – Image Signing & Provenance (COSIGN, Sigstore)  
**Domains:** Supply Chain Security  

### Topics
- cosign signing & verification.  
- Supply Chain Levels (SLSA, SBOM).  

### Labs
- cosign sign `nginx:secure`.  
- Enforce verified images via Kyverno.  

### Active Recall
1. COSIGN vs Notary?  
2. Why SBOM critical?  

### Challenge
- Attacker injects unverified image. How enforce cluster-wide trust?

---

## 📅 Day 12 – Audit Logging & Auditd  
**Domains:** Monitoring, System Hardening  

### Topics
- K8s audit logs.  
- Audit policies.  
- Use of Auditd for syscall-level tracing.  

### Labs
- Enable audit logs in kube-apiserver.  
- Capture "secrets access" events.  

### Active Recall
1. Default audit log location?  
2. Why rate-limiting audit logs important?  

### Challenge
- Regulators request 90-day audit. Cluster only configured default. What now?

---

## 📅 Day 13 – Falco Rules Intro  
**Domains:** Runtime Security, Monitoring  

### Topics
- Falco architecture.  
- Out-of-the-box rules (write below /bin).  

### Labs
- Install Falco daemonset.  
- Trigger Falco by writing to `/etc` inside pod.  

### Active Recall
1. Falco detection method?  
2. Why daemonset deployment?  

### Challenge
- Finance team alerts require custom Falco rule. How integrate without false positives?

---

## 📅 Day 14 – Kubernetes API Server Logging & Forensics  
**Domains:** Monitoring, Logging  

### Topics
- etcd events security.  
- Logging kube-apiserver requests.  

### Labs
- Enable request/response logging.  
- Audit suspicious requests.  

### Active Recall
1. Why excessive API logs dangerous?  
2. What’s forensic value of kube-apiserver logs?  

### Challenge
- Insider using stolen kubeconfig. How detect and cut session?

---

## 📅 Day 15 – Container Runtime Security (Docker, containerd, CRI-O)  
**Domains:** Runtime Security, System Hardening  

### Topics
- containerd config hardening.  
- Preventing root escalation.  

### Labs
- Harden containerd with seccomp default.  
- Test privileged pod denied syscalls.  

### Active Recall
1. containerd vs CRI-O security?  
2. Common misconfigs?  

### Challenge  
- Security mandates move off Docker to CRI-O. Plan?

---

## 📅 Day 16 – Service Mesh Security (mTLS with Istio/Linkerd)  
**Domains:** Runtime Security, Monitoring  

### Topics
- mTLS encryption in service mesh.  
- Zero trust networking.  

### Labs
- Deploy Istio. Enable mTLS for namespace.  
- Validate traffic encrypted.  

### Active Recall
1. Why service mesh for east-west traffic?  
2. Performance tradeoffs?  

### Challenge
- PCI-DSS requires encrypted in-cluster comms. Service mesh solution?

---

## 📅 Day 17 – Ingress & API Gateway Security  
**Domains:** Cluster Setup, Runtime  

### Topics
- Ingress security, TLS termination.  
- WAF integration.  

### Labs
- Deploy NGINX ingress controller with TLS.  
- Enforce `sameSite=strict` cookie.  

### Active Recall
1. TLS passthrough vs termination?  
2. Why TLS in ingress pod important?  

### Challenge
- Zero-day in ingress image. How rollback and re-secure?

---

## 📅 Day 18 – Supply Chain: CI/CD Security  
**Domains:** Supply Chain Security  

### Topics
- Secure pipelines.  
- Secrets in CI/CD.  

### Labs
- Integrate Trivy scanning into GitHub Actions.  
- Break build on CVEs.  

### Active Recall
1. Where secrets leaks in pipelines?  
2. Difference: build-time vs deploy-time scanning?  

### Challenge
- CI/CD compromised with malicious push. Detection & fix?

---

## 📅 Day 19 – Multi-Tenancy Cluster Security  
**Domains:** System Hardening, Runtime  

### Topics
- Namespaces as tenants.  
- LimitRange, ResourceQuotas.  

### Labs
- Apply ResourceQuota to namespace.  
- Verify CPU/memory caps.  

### Active Recall
1. Risks of single-tenant design?  
2. Isolation methods?  

### Challenge
- SaaS requires strong tenant isolation. Cluster design?

---

## 📅 Day 20 – Threat Detection Playbooks  
**Domains:** Monitoring, Runtime  

### Topics
- Integrating Falco with SIEM.  
- Security playbooks.  

### Labs
- Forward Falco alerts to Elasticsearch.  
- Correlate event in Kibana.  

### Active Recall
1. Role of SIEM?  
2. Why integration critical?  

### Challenge
- Real-time containment of malicious pod in prod?

---

## 📅 Day 21 – Secrets Rotation & Vault  
**Domains:** System Hardening  

### Topics
- HashiCorp Vault.  
- Dynamic secrets.  

### Labs
- Deploy Vault injector.  
- Mount DB creds in pod via Vault.  

### Active Recall
1. Why rotation important?  
2. Kubernetes auth in Vault?  

### Challenge
- DB credentials leaked. Plan rotation without downtime?

---

## 📅 Day 22 – Cluster Upgrade & Patching  
**Domains:** Cluster Setup, System Hardening  

### Topics
- Kubernetes upgrade security patches.  
- OS patch cycle.  

### Labs
- kubeadm upgrade.  
- Node drain + patch.  

### Active Recall
1. Drain command?  
2. Why lag in patch dangerous?  

### Challenge
- CVE released for kubelet. Roll strategy?

---

## 📅 Day 23 – Supply Chain: SBOM + Dependency Tracking  
**Domains:** Supply Chain Security  

### Topics
- SBOM with Syft.  
- Dependency scanning.  

### Labs
- Generate SBOM for custom image.  
- Upload to artifact registry.  

### Active Recall
1. SBOM purpose?  
2. Risks of unknown deps?  

### Challenge
- Supply chain executive order requires SBOM. Rollout?

---

## 📅 Day 24 – Security Monitoring with Prometheus + Alerts  
**Domains:** Monitoring  

### Topics
- Metrics-based security alerts.  
- Prometheus rules.  

### Labs
- Add alert on kube-apiserver 401 requests.  
- Fire alert to Alertmanager → Slack.  

### Active Recall
1. Prometheus role?  
2. Why combine with Falco?  

### Challenge
- Too many alert false positives. Fix strategy?

---

## 📅 Day 25 – EFK Stack for Audit Logs  
**Domains:** Monitoring, Logging  

### Topics
- ElasticSearch, Fluentd, Kibana.  
- Centralized log retention.  

### Labs
- Deploy EFK.  
- View pod exec audit logs in Kibana.  

### Active Recall
1. Why Fluentd DaemonSet?  
2. Why index rolling important?  

### Challenge
- Sec team requests 6-month retention. Optimize EFK?

---

## 📅 Day 26 – Multi-Cloud & Managed K8s Security  
**Domains:** Cluster Setup, Runtime  

### Topics
- GKE/EKS/AKS security differences.  
- IAM integration.  

### Labs
- Setup restricted EKS cluster.  
- IAM roles for service accounts.  

### Active Recall
1. IAM vs Kubernetes RBAC?  
2. Cloud-managed challenges?  

### Challenge
- Multi-cloud SaaS. Ensure identity consistency?

---

## 📅 Day 27 – Incident Response in Clusters  
**Domains:** Runtime, Monitoring  

### Topics
- Response playbooks.  
- Forensic capture of pods.  

### Labs
- Use `kubectl-debug` on suspicious pod.  
- Dump memory/process → save evidence.  

### Active Recall
1. Why debug ephemeral container valuable?  
2. How preserve chain of custody?  

### Challenge
- Compromised pod discovered. Steps before kill?

---

## 📅 Day 28 – Advanced Network Security  
**Domains:** Runtime, Monitoring  

### Topics
- eBPF observability & security.  
- Cilium advanced L7 rules.  

### Labs
- Deploy Cilium.  
- Enforce DNS restrictions from pods.  

### Active Recall
1. Why eBPF powerful?  
2. Cilium vs iptables?  

### Challenge
- Enterprises restrict by FQDN. Achieve in K8s?

---

## 📅 Day 29 – Final Review & Exam Simulation  
**Domains:** All  

### Topics
- Review CIS benchmarks.  
- Review RBAC, seccomp, NetworkPolicies.  
- CKS exam speed strategy.  

### Labs
- Simulated 2hr lab exam with ~10 tasks.  

### Active Recall
- Practice RBAC, policies, scanning.  

### Challenge
- Design single compliant architecture for fintech SaaS.

---

## 📅 Day 30 – Full 4-Hour Mock CKS Exam  
**Domains:** All  

### Topics
- Simulate exam with realistic tasks.  
- Hands-on across all domains.  

### Labs
- 4h exam sim:  
- Secure workloads, write pod policies, scan images, enable audit logs, patch kubelet, enforce RBAC.  

### Challenge
- Architect-level scenario: takeover detection & mitigation in multi-tenant cluster.

---

# 🛠️ Tools

### Industry Tools
- **Runtime Security:** Falco, Sysdig Secure, Aqua, Prisma Cloud.  
- **Policy:** OPA, Kyverno, Styra DAS.  
- **Monitoring:** Prometheus, Grafana, EFK.  
- **Supply chain:** Trivy, Grype, COSIGN, Snyk.  
- **Hardening:** kube-bench, kube-hunter.  
- **Isolation:** AppArmor, Seccomp, gVisor, Kata.  

### CKS Exam Tools
- **kube-bench**  
- **kubectl-debug**  
- **Trivy**  
- **Falco**  
- **OPA/Gatekeeper**  
- **Kyverno**  
- **AppArmor, Seccomp**  
- **Auditd, Audit Logs**

---

# ✅ Conclusion
This **30-day neuro-optimized plan** mixes **learning + labs + recall + enterprise scenarios**. You’ll be ready for **CKS speed** and **10-year architect-level production security expertise**.  

