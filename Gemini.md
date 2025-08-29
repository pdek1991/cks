🚀 CKS 30-Day Neuro-Optimized Study Guide
Introduction from Your Mentor
Hello. The CKS exam is a hands-on, problem-solving challenge. You are not just a test-taker; you are a first responder, a solutions architect, and a security engineer all in one. My goal is to teach you how to think like one.
The labs in this guide are your proving ground. Don't just copy-paste the commands; understand why you are running them. The "Very Hard Challenge Questions" are the core of this plan—they simulate the complex, multi-layered problems you will face in the exam and in the real world. You will often need to combine tools and concepts from different domains to solve them.
Let's begin.
Week 1: Foundations & Hardening
Day 1
 * Domains: Cluster Setup, System Hardening
 * Topics: kube-bench for CIS Benchmark checks, etcd and API Server hardening (--tls-private-key, --etcd-cafile), RBAC basics (Roles, RoleBindings).
 * Interleaved Learning Notes: We start with the core. The CIS Kubernetes Benchmark provides a checklist for securing your cluster. We use kube-bench to automate this. Simultaneously, we'll introduce the foundational security control in Kubernetes: RBAC. Understanding how the API server authenticates and authorizes requests is the first step to securing it.
 * Hands-on Labs:
   * docker run --rm -it --net host --pid host -v /etc:/etc -v /var/lib:/var/lib aquasec/kube-bench:latest - Run kube-bench to get a report.
   * Manually inspect the kube-apiserver manifest on a control plane node. Note the flags for TLS.
   * Create a Role that can only view pods in a specific namespace. Create a ServiceAccount and a RoleBinding to grant it this access.
   * Use kubectl auth can-i get pods --as system:serviceaccount:default:my-sa to test the permissions.
 * Active Recall Questions:
   * What is the purpose of the CIS Kubernetes Benchmark?
   * How would you secure the etcd endpoint from unauthorized access?
   * Explain the difference between a Role and a ClusterRole.
 * Very Hard Challenge Question: A new developer needs access to view logs across all namespaces. Design and implement the RBAC resources (ClusterRole, ClusterRoleBinding, and ServiceAccount) to grant this access with the principle of least privilege, and explain why a Role is insufficient here.
Day 2
 * Domains: Minimize Microservice Vulnerabilities, Supply Chain Security
 * Topics: Pod Security Contexts (runAsNonRoot, readOnlyRootFilesystem), basic image scanning with trivy.
 * Interleaved Learning Notes: Security starts at the microservice level. We'll secure the pod itself using the securityContext field. Concurrently, we introduce Supply Chain Security—before a pod is even deployed, we must ensure its container image is free of vulnerabilities. trivy is the go-to tool for this.
 * Hands-on Labs:
   * Create a Pod manifest that uses securityContext to set runAsNonRoot: true and readOnlyRootFilesystem: true.
   * Attempt to exec into the pod and create a file. Observe the read-only file system error.
   * Run trivy image nginx:latest to scan a common image. Interpret the report.
   * Scan a more vulnerable image like docker.io/library/httpd:2.4.58 and identify critical vulnerabilities.
 * Active Recall Questions:
   * What is the primary benefit of setting readOnlyRootFilesystem: true?
   * How does trivy help mitigate supply chain attacks?
   * What is the allowPrivilegeEscalation field and why is it important?
 * Very Hard Challenge Question: A developer team is deploying a container that requires access to a specific directory on the host /var/log/app. Describe how you would configure the Pod's securityContext to allow this while still adhering to a "least privilege" model.
Day 3
 * Domains: Cluster Setup, System Hardening
 * Topics: Pod Security Admission (PSA), Node Hardening (no sudo or SSH for pods), kubelet hardening (--authorization-mode, --read-only-port).
 * Interleaved Learning Notes: We are moving from a single pod's security to securing the nodes and the cluster itself. PSA is the modern replacement for Pod Security Policies (PSPs). We will also look at the kubelet, the agent on every node that can be a major attack vector if not hardened properly.
 * Hands-on Labs:
   * Configure a namespace to enforce Pod Security Admission at the baseline level. Try to deploy a pod that violates this policy (e.g., uses hostPath).
   * Inspect the kubelet service manifest and identify key security flags like read-only-port=false and authorization-mode=Webhook.
   * Disable SSH on a test node and configure a jump box or bastion host for access.
 * Active Recall Questions:
   * What are the three Pod Security Admission levels and what is the difference between enforce and audit?
   * Why is it a security best practice to disable the read-only port on the kubelet?
   * What is the primary risk of allowing privileged pods?
 * Very Hard Challenge Question: A legacy application requires access to the host's /dev/shm to function. Design a custom Pod Security Admission policy that allows this specific hostPath for a single application namespace, while preventing its use in all other namespaces. Explain your approach and why this is a risk.
Day 4
 * Domains: Supply Chain Security, Minimize Microservice Vulnerabilities
 * Topics: Admission Controllers (Mutating and Validating), OPA/Gatekeeper for policy enforcement.
 * Interleaved Learning Notes: We have a vulnerability scanner (trivy), but how do we prevent vulnerable images from ever being deployed? We use an Admission Controller like OPA/Gatekeeper. This is a critical architectural pattern for ensuring policy as code. It's the "prevention" part of our defense-in-depth strategy.
 * Hands-on Labs:
   * Install OPA/Gatekeeper using Helm or kubectl apply.
   * Create a simple ConstraintTemplate and Constraint to enforce that all pod manifests must have the app.kubernetes.io/name label.
   * Try to deploy a pod without the label and observe the rejection.
 * Active Recall Questions:
   * What is the difference between a ValidatingAdmissionWebhook and a MutatingAdmissionWebhook?
   * How does OPA/Gatekeeper improve security beyond just trivy?
   * What is the purpose of ConstraintTemplates in OPA/Gatekeeper?
 * Very Hard Challenge Question: A new corporate policy dictates that all container images must come from a trusted, private registry (my.registry.com). Write the OPA/Gatekeeper ConstraintTemplate and Constraint to enforce this rule and reject any deployment attempting to pull from docker.io or any other external registry.
Day 5
 * Domains: System Hardening, Cluster Setup
 * Topics: AppArmor and Seccomp for mandatory access control, NetworkPolicy basics.
 * Interleaved Learning Notes: We are now looking at the kernel-level security of our containers. AppArmor and Seccomp are powerful tools for restricting the system calls a container can make. We'll also introduce NetworkPolicy—the key to micro-segmentation in Kubernetes.
 * Hands-on Labs:
   * Create a pod manifest with a securityContext that references an AppArmor profile.
   * On a test host, load a simple AppArmor profile that denies file writing.
   * Create a pod with seccompProfile configured to RuntimeDefault or localhost/my-profile.
   * Deploy a NetworkPolicy to restrict traffic between two pods in the same namespace.
 * Active Recall Questions:
   * Explain the difference between AppArmor and Seccomp.
   * What is the benefit of using seccompProfile: unconfined? (Trick question!)
   * How can NetworkPolicy help prevent a single compromised pod from accessing other services?
 * Very Hard Challenge Question: An attacker has compromised a pod in the web namespace. This pod needs to communicate with a database in the db namespace. Design a NetworkPolicy that only allows traffic from the compromised pod to the database on a specific port (3306), and nothing else. Explain how this policy protects the cluster from a lateral movement attack.
Week 2: Runtime & Supply Chain Deep Dives
Day 6
 * Domains: Supply Chain Security, Runtime Security
 * Topics: Advanced trivy (scanning git repos, SBOMs), Falco for real-time threat detection.
 * Interleaved Learning Notes: trivy is not just for images. We can use it to scan our source code and IaC. We also introduce Falco, the gold standard for runtime security. Falco watches for anomalous behavior inside containers, acting as an early warning system.
 * Hands-on Labs:
   * Run trivy fs /path/to/my/git/repo to scan a local source code directory.
   * Generate a Software Bill of Materials (SBOM) for a container image using trivy image --format spdx-json -o sbom.json myimage.
   * Install Falco and its dependencies on a cluster.
   * Trigger a default rule by trying to exec into a pod and writing to a forbidden directory (/etc). Observe the Falco alert.
 * Active Recall Questions:
   * What is a Software Bill of Materials (SBOM) and why is it important for supply chain security?
   * How is Falco different from an admission controller?
   * What kernel components does Falco rely on?
 * Very Hard Challenge Question: An attacker is attempting to run a port scanner (nmap) from within a compromised pod. Write a custom Falco rule to detect this activity and alert the security team. Explain what syscalls you would be looking for.
Day 7
 * Domains: Cluster Setup, System Hardening
 * Topics: Advanced RBAC (User vs Group, system: groups), Certificate Signing Requests (CSRs).
 * Interleaved Learning Notes: We are now going deep into how Kubernetes manages its own identity and authentication. The system: groups (system:masters, system:nodes) are critical to understand for cluster security. We will also manually manage a Certificate Signing Request to understand the lifecycle of client certificates.
 * Hands-on Labs:
   * List all ClusterRoleBindings to identify who has system:masters access.
   * Create a user (bob) with a private key.
   * Manually create a CertificateSigningRequest for bob and approve it.
   * Use kubectl with bob's new certificate to test access.
 * Active Recall Questions:
   * What is the primary purpose of the system:masters group?
   * How can you grant a group of users access to a cluster without creating individual ClusterRoleBindings?
   * When would you use a CertificateSigningRequest instead of a service account?
 * Very Hard Challenge Question: An attacker has managed to obtain a ServiceAccount from a pod. Design an RBAC strategy using kubectl commands to revoke all access for this ServiceAccount and its RoleBindings across all namespaces, ensuring no other services are affected.
Day 8
 * Domains: Minimize Microservice Vulnerabilities, Supply Chain Security
 * Topics: Kyverno vs OPA/Gatekeeper, Network Policies with different selectors (podSelector, namespaceSelector).
 * Interleaved Learning Notes: Kyverno is another powerful policy engine that is often simpler and more "Kubernetes-native" than OPA/Gatekeeper. It's important to know both. We'll also take NetworkPolicy to the next level by controlling traffic across namespaces.
 * Hands-on Labs:
   * Install Kyverno using Helm.
   * Create a ClusterPolicy that validates that all images come from a specific registry. Compare this to your OPA/Gatekeeper work.
   * Deploy three namespaces: frontend, backend, database. Create NetworkPolicies that allow frontend to talk to backend but not database, and allow backend to talk to database but not frontend.
 * Active Recall Questions:
   * What are the key advantages of Kyverno over OPA/Gatekeeper for a Kubernetes beginner?
   * What is the purpose of an Egress rule in a NetworkPolicy?
   * When would a namespaceSelector be more useful than a podSelector?
 * Very Hard Challenge Question: A new application team requires their pods to access a shared NFS volume via a hostPath. Design and implement a Kyverno policy that allows this specific hostPath only for pods in the storage-consumers namespace and blocks it everywhere else.
Day 9
 * Domains: Runtime Security, Monitoring & Logging
 * Topics: Advanced Falco rules, auditd and Kubernetes Audit Logs.
 * Interleaved Learning Notes: Falco is powerful, but you need to write custom rules to catch sophisticated attacks. We'll also examine the Kubernetes Audit Log, which is a rich source of security events. The logs will tell us what happened, while Falco tells us what is happening now.
 * Hands-on Labs:
   * Enable and inspect the Kubernetes Audit Log on the API Server.
   * Write a custom Falco rule to detect when a kubectl command attempts to delete a pod in a specific namespace (production).
   * Force a failed kubectl delete command and check both the Falco output and the Kubernetes Audit Log.
 * Active Recall Questions:
   * What information is typically found in a Kubernetes Audit Log entry?
   * How would you configure auditd on the underlying host to monitor for suspicious activity?
   * What is the difference between Falco and a traditional SIEM?
 * Very Hard Challenge Question: A security incident report states that a malicious actor tried to create a ClusterRoleBinding with system:masters access. Using only the Kubernetes Audit Logs, describe the steps you would take to identify the user responsible, the timestamp of the event, and the full details of the attempted operation.
Day 10
 * Domains: System Hardening, Minimize Microservice Vulnerabilities
 * Topics: kube-bench output analysis and remediation, gVisor and sandboxing runtimes.
 * Interleaved Learning Notes: We'll circle back to kube-bench and actually fix the findings. This is the practical side of system hardening. We'll also introduce advanced container sandboxing with gVisor, which provides a much stronger isolation boundary than traditional namespaces and cgroups.
 * Hands-on Labs:
   * Run kube-bench and identify at least three WARN or FAIL findings.
   * Manually remediate the findings (e.g., set the kubelet read-only port to false).
   * Install a gVisor runtime.
   * Deploy a pod using the gVisor runtime and compare its isolation properties to a standard runc container.
 * Active Recall Questions:
   * How would you automate the remediation of kube-bench findings?
   * Explain the concept of a container sandbox and how gVisor implements it.
   * What is the performance trade-off of using a sandbox runtime like gVisor?
 * Very Hard Challenge Question: A developer needs to run a third-party, untrusted container in your cluster. Design an architectural solution that uses gVisor to isolate the container and a NetworkPolicy to restrict its outbound traffic. Describe the security benefits of this layered approach.
Week 3: Advanced Architecting & Tool Integration
Day 11
 * Domains: Runtime Security, Cluster Setup
 * Topics: kubectl-debug for security investigation, advanced ServiceAccount and Token security.
 * Interleaved Learning Notes: kubectl-debug is a crucial exam tool. It lets you troubleshoot and investigate inside a container without disrupting it. We'll also secure our ServiceAccounts by understanding how tokens are mounted and how to manage their lifecycles.
 * Hands-on Labs:
   * Install kubectl-debug.
   * Use kubectl-debug to attach to a running pod and investigate a process.
   * Create a ServiceAccount with a specific expiration time for its token.
   * Describe a pod's manifest and find the ServiceAccount token mount.
 * Active Recall Questions:
   * When would you use kubectl-debug instead of kubectl exec?
   * What is the risk of a ServiceAccount token being exfiltrated from a pod?
   * How can you disable the automatic mounting of a ServiceAccount token in a pod?
 * Very Hard Challenge Question: An investigation is underway regarding a compromised pod. Using kubectl-debug, describe the commands you would use to: 1) inspect the running processes, 2) check the ServiceAccount token and its mounted permissions, and 3) review recent file system changes, all without stopping the original container.
Day 12
 * Domains: Monitoring & Logging, Runtime Security
 * Topics: auditd on the host, CIS Kubernetes Benchmark for Nodes, kube-bench for worker nodes.
 * Interleaved Learning Notes: The underlying nodes are just as important as the cluster. We'll use auditd to monitor the host itself for suspicious activity (e.g., changes to /etc/docker). We'll also use kube-bench to check the CIS Benchmark for the worker nodes.
 * Hands-on Labs:
   * Install auditd on a test host.
   * Create a rule to monitor for file modifications to /etc/docker and /var/lib/kubelet.
   * Run kube-bench node to check the CIS Benchmark for a single node.
   * Manually trigger a finding and check the auditd logs.
 * Active Recall Questions:
   * How is auditd on the host different from Kubernetes Audit Logs?
   * What are some key security recommendations for a Kubernetes worker node?
   * What is the purpose of kube-bench node vs kube-bench master?
 * Very Hard Challenge Question: A security alert from auditd shows that a user has modified a file in /var/lib/kubelet. What specific log entries would you look for, and what kubectl commands would you run to correlate this event with potential malicious activity in the cluster?
Day 13
 * Domains: Supply Chain Security, Minimize Microservice Vulnerabilities
 * Topics: Image Signing and Verification (Notary, Sigstore), Admission Controllers for verification.
 * Interleaved Learning Notes: We now have image scanning and admission control, but what if a compromised image is deployed with a clean bill of health? Image signing ensures the image's authenticity and integrity. We'll use an admission controller to enforce that only signed images can be deployed.
 * Hands-on Labs:
   * Using a tool like cosign (part of Sigstore), sign a container image.
   * Create a Kyverno or OPA/Gatekeeper policy to verify the signature of a deployed image.
   * Attempt to deploy a non-signed image and observe the rejection.
 * Active Recall Questions:
   * What is the difference between a container image's integrity and its authenticity?
   * How does a Sigstore-signed image provide better security than a simple hash check?
   * What are the three main components of Sigstore?
 * Very Hard Challenge Question: A corporate policy requires that all production container images must be signed by two distinct parties: a "builder" key and a "security" key. Design and implement an admission controller policy that enforces this dual-signature requirement.
Day 14
 * Domains: Cluster Setup, Monitoring & Logging
 * Topics: TLS for Ingress/Egress, securing the control plane components (scheduler, controller-manager), Falco output to syslog.
 * Interleaved Learning Notes: Security isn't just about pods; it's about the communication between all components. We'll secure traffic with TLS and harden the other control plane components. We'll also configure Falco to send its output to a more persistent logging system.
 * Hands-on Labs:
   * Configure a basic Ingress resource with TLS.
   * Inspect the manifests for kube-scheduler and kube-controller-manager for security flags.
   * Configure Falco to send its alerts to syslog or a file that can be scraped by a SIEM.
 * Active Recall Questions:
   * What is the primary security benefit of using TLS on an Ingress controller?
   * What is the purpose of the kube-controller-manager and why does it need to be secured?
   * Why is it a bad practice to rely solely on Falco's local output for security monitoring?
 * Very Hard Challenge Question: An attacker has obtained access to a worker node. They are trying to spoof API calls to the kube-scheduler. Describe the security configurations (in the scheduler manifest) that would prevent this, and what kind of Falco or Audit Log events you would look for to detect the attempt.
Day 15
 * Domains: All Domains
 * Topics: Mid-point Review & Integration.
 * Interleaved Learning Notes: This is your first major review day. We'll take a step back and connect all the dots. We've covered securing the cluster from the API server to the individual container, and from design time to runtime.
 * Hands-on Labs:
   * Run kube-bench again and compare the report to Day 1.
   * Use kubectl-debug on a pod that has a securityContext and a seccompProfile. Verify the security restrictions from inside the pod.
   * Review all the NetworkPolicy and Falco rules you have created.
 * Active Recall Questions:
   * Summarize the security benefits of NetworkPolicy, Falco, and OPA/Gatekeeper, and how they work together in a layered defense.
   * Explain the concept of "least privilege" in the context of RBAC and Pod Security.
   * What is the biggest security gap if you only use trivy and no admission controller?
 * Very Hard Challenge Question: A developer team is deploying a new microservice. It requires privileged access to the host's /proc directory for monitoring, needs to communicate with an external API, and must be deployed with an image from a non-approved registry. As the security architect, design a multi-layered plan using OPA/Gatekeeper, NetworkPolicy, gVisor, and AppArmor to secure this application while still allowing its required functionality.
Week 4: Exam Simulation & Final Review
Day 16-20
 * Domains: All Domains
 * Topics: Full-scale mock exams from various providers (e.g., Killer Shell, KodeKloud, etc.), timed drills for specific topics.
 * Interleaved Learning Notes: The focus now is on speed and recall under pressure. Practice, practice, practice. You should be able to solve complex problems by combining the tools you've learned without hesitation. Use kubectl-debug, trivy, kube-bench, Falco on-the-fly to solve problems.
 * Hands-on Labs:
   * Complete at least one full CKS mock exam per day.
   * Spend 30 minutes on a specific weak point (e.g., writing a complex NetworkPolicy from memory).
 * Very Hard Challenge Questions:
   * Scenario 1: You are called to a security incident. A Falco alert indicates a shell has spawned inside a container running as root. The container should not be running as root. You must: 1) Identify the misconfigured pod. 2) Use kubectl-debug to investigate the running process. 3) Write a Kyverno policy to prevent such misconfigurations in the future.
   * Scenario 2: An attacker has exploited a vulnerability to get a shell inside a pod and has found the ServiceAccount token. The attacker is trying to pivot to the API server. Using your knowledge of RBAC, Audit Logs, and kubectl auth, explain how you would: 1) Check the permissions of the compromised ServiceAccount. 2) Identify any successful or failed API calls made by the attacker. 3) Revoke the compromised token and its access.
Day 21-25
 * Domains: All Domains
 * Topics: Advanced review of specific, tricky topics.
 * Interleaved Learning Notes: You'll have identified your weak spots by now. This is the time to nail them down. Focus on the subtle differences between tools (OPA vs Kyverno), the syntax of Falco rules, and the structure of NetworkPolicy selectors.
 * Hands-on Labs:
   * Create and debug complex NetworkPolicies that use multiple selectors.
   * Write a Falco rule from scratch and test it.
   * Re-run kube-bench and fix all remaining findings.
 * Very Hard Challenge Questions:
   * Scenario 1: A Falco alert for a file_change is not providing enough context. Describe how you would integrate the Auditd logs on the host to provide a more complete picture of the security event.
   * Scenario 2: You need to create a NetworkPolicy to allow a pod to receive inbound traffic only from pods with a specific label, but only if they are in a different namespace that is also labeled with team: security. Write the NetworkPolicy YAML.
Day 26-30
 * Domains: All Domains
 * Topics: Final review, exam tips, and mental preparation.
 * Interleaved Learning Notes: Spend these last days going over the official CKS curriculum and practice questions. Focus on the core competencies: kubectl-debug, kube-bench, trivy, Falco, AppArmor, Seccomp, NetworkPolicy, and Admission Controllers.
 * Hands-on Labs:
   * Complete 2-3 final mock exams.
   * Take a break on Day 29.
   * On Day 30, review the official CKS documentation and tool list.
 * Very Hard Challenge Question:
   * Final Scenario: Your production cluster is under attack. Falco is reporting a port_scan_detected event from a pod in the staging namespace, and the Kubernetes Audit Logs are showing failed attempts to delete clusterroles. As the security architect, provide a step-by-step plan for containment, investigation, and remediation, using all the tools and knowledge you have gained over the last 30 days.
🛠️ Tools Section
Tools Used in Industry
This list is a small sample of what an enterprise-grade Kubernetes security stack might include.
 * Image Scanning: Trivy, Snyk, Clair, Grype
 * Admission Control: OPA/Gatekeeper, Kyverno, Pod Security Admission
 * Runtime Security: Falco, Aqua Security (Tracee, Trivy), Sysdig Secure
 * Network Security: Calico, Cilium, Istio (Service Mesh)
 * Monitoring & Auditing: Prometheus, Fluentd, Grafana, Splunk, Datadog
 * Secret Management: HashiCorp Vault, External Secrets
 * Cloud Provider Tools: GKE Security Posture, AWS GuardDuty for EKS
Tools Required/Recommended for the CKS Exam
The CKS exam is very specific about the tools you will need to know. The following list is based on the official CKS curriculum and recent exam feedback. You MUST be proficient in these.
 * kubectl
 * kube-bench
 * kubectl-debug
 * trivy
 * Falco
 * AppArmor
 * Seccomp
 * auditd
 * NetworkPolicy
 * OPA/Gatekeeper or Kyverno (often one or the other)
 * Basic understanding of etcd, kubelet, kube-apiserver security configurations
 * A Linux command-line environment (vim, grep, sed, etc.)
