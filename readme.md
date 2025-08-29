# 🛡️ CKS 30-Day Neuro-Optimized Study Blueprint

This plan applies **spaced repetition, interleaving, active recall, and the Feynman technique** to help you master Kubernetes security in 30 days.  
You already know CKA, so this focuses on **security mastery**.

---

## 📅 Weekly Plan Overview
- **Week 1:** Core Security Fundamentals (RBAC, Pod Security, Network, Images, Runtime)  
- **Week 2:** Policy & Data Security (Admission, OPA, Secrets, TLS, Service Mesh)  
- **Week 3:** Attack/Defense (Privilege Escalation, Escapes, Audit Logs, IR)  
- **Week 4:** Mastery & Exam Prep (Speed drills, Reviews, Mock Exams)  

---

## 🗓️ Daily Breakdown

| Week | Day | Topic | Active Recall Questions |
|------|-----|-------|--------------------------|
| Week 1 | Day 1 | **RBAC & Authorization** | - What is the difference between Role and ClusterRole?<br>- How do you bind a ServiceAccount to a Role?<br>- How can RBAC prevent privilege escalation? |
| Week 1 | Day 2 | **Pod Security Admission & Contexts** | - What replaces PodSecurityPolicies in modern Kubernetes?<br>- What is the difference between privileged and restricted pod security levels?<br>- How do you enforce read-only root filesystem? |
| Week 1 | Day 3 | **Network Policies** | - How does a default-deny NetworkPolicy work?<br>- What is the difference between ingress and egress rules?<br>- How do you allow only namespace-to-namespace traffic? |
| Week 1 | Day 4 | **Image Security (Scanning & Signing)** | - How do you scan container images for vulnerabilities?<br>- What tools can be integrated (Trivy, Clair, Anchore)?<br>- How do you enforce signed images in Kubernetes? |
| Week 1 | Day 5 | **Runtime Security (seccomp, AppArmor, Falco)** | - What is seccomp and how is it applied to pods?<br>- What are AppArmor profiles?<br>- How does Falco detect runtime anomalies? |
| Week 1 | Day 6–7 | **Revision + Mini Mock** | - Revisit flashcards (RBAC, Pod Security, NetPol).<br>- Lab: Break/fix RBAC & NetPol.<br>- Mini 30-min mock scenario. |
| Week 2 | Day 8 | **Admission Controllers & OPA Gatekeeper** | - What is an admission controller in Kubernetes?<br>- How does OPA/Gatekeeper enforce custom policies?<br>- What is the difference between mutating and validating admission webhooks? |
| Week 2 | Day 9 | **Secrets Management** | - How does Kubernetes encrypt secrets at rest?<br>- What is the difference between Secrets and ConfigMaps?<br>- What are SealedSecrets and how are they used? |
| Week 2 | Day 10 | **TLS, Certificates & Service Mesh** | - How does Kubernetes manage TLS certificates?<br>- What is mTLS and how is it enforced in Istio/Linkerd?<br>- How do you rotate expired TLS certificates in Kubernetes? |
| Week 2 | Day 11–12 | **Interleaving Labs** | - Combine: Admission + Secrets + TLS.<br>- Lab: Enforce policy to block root containers, seal a secret, configure mTLS. |
| Week 2 | Day 13–14 | **Feynman Review** | - Summarize week in plain words.<br>- Teach: “Kubernetes Security in 15 min.” |
| Week 3 | Day 15 | **Attack Scenarios (Privilege Escalation, Escape)** | - How could a pod escape to the host system?<br>- What permissions lead to privilege escalation?<br>- How do you detect and mitigate a malicious DaemonSet? |
| Week 3 | Day 16 | **Monitoring & Audit Logs** | - What is the purpose of Kubernetes audit logs?<br>- How do you configure Falco rules for suspicious activities?<br>- What tools can you use for runtime monitoring? |
| Week 3 | Day 17 | **Incident Response** | - How do you isolate a compromised pod?<br>- What is the process for forensic analysis in Kubernetes?<br>- How do you rollback from a malicious deployment? |
| Week 3 | Day 18–19 | **Attack/Defense Lab** | - Red team: Exploit misconfigured pod.<br>- Blue team: Detect with Falco, block with policies. |
| Week 3 | Day 20–21 | **Full Mock Exam** | - 2-hour exam simulation.<br>- Post-mortem analysis with Feynman technique. |
| Week 4 | Day 22 | **Exam Speed Optimization** | - What kubectl aliases help reduce typing?<br>- How does `--dry-run=client` help create manifests fast?<br>- What is the fastest way to apply YAML from stdin? |
| Week 4 | Day 23 | **Review RBAC + NetPol + Secrets** | - Quick-fire recall drills.<br>- Flashcard reinforcement. |
| Week 4 | Day 24–25 | **Kubectl Speed Drills** | - Lab: Solve 5 practice tasks in <5 min.<br>- Optimize one-liners & shortcuts. |
| Week 4 | Day 26–27 | **Red Team Final Lab** | - Attack: Deploy malicious pod.<br>- Defend: Harden with RBAC + PSA + NetPol. |
| Week 4 | Day 28 | **Mock Exam #2** | - Another 2-hour simulation. |
| Week 4 | Day 29 | **Mock Exam #3** | - Final polish under exam conditions. |
| Week 4 | Day 30 | **Feynman Graduation** | - Teach: “Kubernetes Security in 30 min” to imaginary student.<br>- Revise weak areas. |

---

## 🔑 Tools & Methods
- **Spaced Repetition** → Use Anki for RBAC verbs, PSA levels, NetPol rules.  
- **Interleaving** → Always mix 2 domains (e.g., Admission + Secrets, Network + Runtime).  
- **Feynman Notebook** → Explain every topic in your own words daily.  
- **Active Recall** → Self-quiz with the provided questions.  
- **Mocks** → Use [Killer.sh CKS](https://killer.sh) and practice clusters.  

---