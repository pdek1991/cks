## 🔹 Cluster Hardening

## 🔹  Use Role Based Access Controls to minimize exposure

✅	Use Role Instead of ClusterRole Whenever Possible
✅	Restrict Service Accounts with Least Privilege
✅	Disable Auto-Mounting of Service Account Tokens
✅	Enforce Read-Only Access for Non-Privileged Users
✅	Regularly Audit and Review RBAC Permissions


## 🔹 Service Account
✅	Rotate Service Account Tokens
✅	Disable the default service account in namespaces
✅	Minimize permissions for new service accounts
✅	Audit service account usage regularly
✅  SA token is mounted at /var/run/secrets/kubernetes.io/serviceaccount/
✅  Disable service account automount at service account level and at pod level
✅  Use custom service accounts instead of the default one


## 🔹 Restrict access to Kubernetes API
1 Use Role-Based Access Control (RBAC) to Restrict API Access
2 Restrict API Access with Network Policies (Cluster Network Isolation)
3 Restrict Access with API Server Admission Controllers
4 Enable NodeRestriction (Prevents Pods from Impersonating Other Nodes)
5 Restrict API Access with API Server Authentication and Authorization
6 Disable Anonymous and Unauthorized Access
7 Use Firewall Rules to Restrict API Server Access
8 Implement Mutual TLS (mTLS) for Secure API Communication
9 Disable Service Account Token Auto-Mounting
10 Restrict API Access with Pod Security Policies
11 Monitor API Access with Audit Logging
