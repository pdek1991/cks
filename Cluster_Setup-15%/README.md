## 🔹 Fundamentals of Kubernetes Network Policies

	What are Network Policies?

	How Kubernetes controls network traffic at the pod level

	Role of CNI (Container Network Interface) in enforcing NSPs

	Supported CNIs: Calico, Cilium, Weave (Flannel does NOT support NSPs)

	Default behavior of Kubernetes networking (All traffic is allowed unless restricted by NSPs)

## 🔹 Network Policy Components & YAML Structure

	podSelector (Which pods the policy applies to)

	ingress (Defines allowed incoming traffic)

	egress (Defines allowed outgoing traffic)

	policyTypes (Specifies ingress, egress, or both)

	Label-based traffic control

## 🔹 Ingress Network Policies (Restrict Incoming Traffic)

	Creating a Deny-All Ingress policy

	Allowing ingress from specific pods

	Allowing traffic only from a particular namespace

	Combining multiple ingress rules

## 🔹 Egress Network Policies (Restrict Outgoing Traffic)

	Creating a Deny-All Egress policy

	Allowing only specific external traffic (e.g., DNS, API, DBs)

	Namespace-based egress restrictions

## 🔹 Advanced Use Cases & Scenarios

	Namespace isolation using NSPs

	Multi-tier application security (frontend, backend, database)

	Restricting pod-to-pod communication across namespaces

	Implementing Zero Trust networking in Kubernetes

## 🔹 Debugging & Troubleshooting Network Policies

	Using kubectl describe networkpolicy

	Checking applied policies with kubectl get networkpolicy

	Testing pod connectivity using kubectl exec + curl/wget/ping

	Debugging tools for different CNIs:

	calicoctl for Calico

	cilium monitor for Cilium

	Common mistakes and misconfigurations


## 🔹 General Best Practices  

✅ Default Deny-All Policy – Start with a **deny-all** rule and explicitly allow only necessary traffic.  

✅ Least Privilege Model (Zero Trust) – Only allow traffic that is explicitly required.  

✅ Apply Namespace-Based Isolation – Use policies to prevent pods in one namespace from communicating with others.  

✅ Use Labels Effectively – Define pod selectors carefully to apply policies only where needed.  

✅ Minimize Wildcard Usage (`{}`) – Avoid broad, unrestricted network policies.  

---  

## 🔹 Ingress Best Practices  

✅ Block All Unnecessary Ingress Traffic – Use a **deny-all ingress** policy as a starting point.  

✅ Allow Traffic Only from Trusted Pods – Specify **podSelector** rules instead of allowing all traffic.  

✅ Use Namespace Selectors – Restrict access from specific namespaces.  

✅ Limit External Exposure – Allow ingress traffic only from specific IP ranges when necessary.  



## 🔹 Egress Best Practices

✅ Restrict Outbound Traffic – Apply deny-all egress as a baseline.

✅ Allow Only Necessary External Traffic – Define egress policies to restrict external API/database access.

✅ Use DNS-Based Egress Filtering – Some CNIs (e.g., Cilium) support DNS-aware egress rules.

## 🔹 Advanced Best Practices

✅ Limit Cross-Namespace Communication – Use namespaceSelector to prevent unnecessary cross-namespace traffic.

✅ Implement Network Segmentation – Separate frontend, backend, and database layers.

✅ Regularly Audit Network Policies – Use tools like kubectl describe networkpolicy to check applied rules.

✅ Leverage CNI Features – Use Calico, Cilium, or Weave for advanced network security features.


## 🔹Use CIS benchmark to review the security configuration of Kubernetes components 

Kube-Bench tool dwnload link
https://github.com/aquasecurity/kube-bench/releases/download/v0.4.0/kube-bench_0.4.0_linux_amd64.tar.gz

./kube-bench --config-dir `pwd`/cfg --config `pwd`/cfg/config.yaml



## 🔹 Ingress with TLS
✅ Install an Ingress Controller 
	kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/cloud/deploy.yaml

✅ Create a TLS Certificate
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout tls.key -out tls.crt -subj "/CN=mycas.com/O=mycas"
	kubectl create secret tls mycas-tls --key=tls.key --cert=tls.crt

✅ Create deployment and Service
✅ Create Ingress object with TLS 
✅ Update local DNS file and check with NodeIP and verify


## 🔹 Protect metadata endpoint
    AWS: http://169.254.169.254/latest/meta-data/
	GCP: http://169.254.169.254/computeMetadata/v1/
	Azure: http://169.254.169.254/metadata/

✅  NetworkPolicies to Block Metadata Access
✅	Restrict External Access to NodePort Services
✅	Disable Service Account Auto-Mounting
✅	Implement mTLS for Internal Communication


## 🔹 Verify Platform Binaries

✅	https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.32.md download server binaries and verify 	sha512sum
	curl -LO https://dl.k8s.io/release/v1.28.0/bin/linux/amd64/kubectl.sha256

✅	Scan Kubernetes Binaries for Vulnerabilities using trivy
	trivy fs ./kubectl
