1️⃣ Fundamentals of Kubernetes Network Policies

What are Network Policies?

How Kubernetes controls network traffic at the pod level

Role of CNI (Container Network Interface) in enforcing NSPs

Supported CNIs: Calico, Cilium, Weave (Flannel does NOT support NSPs)

Default behavior of Kubernetes networking (All traffic is allowed unless restricted by NSPs)

2️⃣ Network Policy Components & YAML Structure

podSelector (Which pods the policy applies to)

ingress (Defines allowed incoming traffic)

egress (Defines allowed outgoing traffic)

policyTypes (Specifies ingress, egress, or both)

Label-based traffic control

3️⃣ Ingress Network Policies (Restrict Incoming Traffic)

Creating a Deny-All Ingress policy

Allowing ingress from specific pods

Allowing traffic only from a particular namespace

Combining multiple ingress rules

4️⃣ Egress Network Policies (Restrict Outgoing Traffic)

Creating a Deny-All Egress policy

Allowing only specific external traffic (e.g., DNS, API, DBs)

Namespace-based egress restrictions

5️⃣ Advanced Use Cases & Scenarios

Namespace isolation using NSPs

Multi-tier application security (frontend, backend, database)

Restricting pod-to-pod communication across namespaces

Implementing Zero Trust networking in Kubernetes

6️⃣ Debugging & Troubleshooting Network Policies

Using kubectl describe networkpolicy

Checking applied policies with kubectl get networkpolicy

Testing pod connectivity using kubectl exec + curl/wget/ping

Debugging tools for different CNIs:

calicoctl for Calico

cilium monitor for Cilium
Common mistakes and misconfigurations
