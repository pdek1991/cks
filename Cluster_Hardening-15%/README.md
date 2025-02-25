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


## 🔹 Upgrading Kubernetes to v1.32

✅ Update Kubernetes repositories & GPG keys
✅ Upgrade Kubernetes components (kubeadm, kubelet, kubectl)
✅ Follow best practices (Version Skew Policy, Rollback Strategy)
✅ Troubleoot issues in case of upgrade failure

1️⃣ Updating Kubernetes Repository & GPG Key
Step 1: Remove Old Kubernetes Repository & GPG Key

# Remove old repo (if exists)
sudo rm -f /etc/apt/sources.list.d/kubernetes.list

# Remove old GPG key (if stored in apt-key)
sudo apt-key del <old-key-id>  # Replace <old-key-id> with actual key ID

# Remove old key (if stored in /usr/are/keyrings/)
sudo rm -f /etc/apt/keyrings/kubernetes-apt-keyring.gpg
Step 2: Add the Latest Kubernetes Repository

# Create keyrings directory (if not exists)
sudo mkdir -p /etc/apt/keyrings

# Add Kubernetes GPG Key
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.32/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

# Add Kubernetes Repository
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.32/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list
Step 3: Update & Install Kubernetes Packages

# Update package list
sudo apt update

# Install Kubernetes latest version
sudo apt install -y kubeadm kubelet kubectl

# Prevent automatic upgrades (optional)
sudo apt-mark hold kubeadm kubelet kubectl
2️⃣ Best Practices for Kubernetes Upgrade
✅ Version Skew Policy (Kubeadm, Kubelet, Kubectl)
Kubeadm must be upgraded first (can be 1 minor version newer than control plane).
Kubelet must be <=1 minor version behind the control plane.
Kubectl ould match the control plane version.
Component	Allowed Skew	Example
Kubeadm	+1 version	v1.32 Kubeadm with v1.31 Control Plane
Kubelet	-1 version	v1.32 Control Plane with v1.31 Kubelet
Kubectl	Exact Match	v1.32 Control Plane with v1.32 Kubectl
3️⃣ Upgrading Kubernetes Cluster
Step 1: Drain the Control Plane Node

kubectl drain <control-plane-node> --ignore-daemonsets --delete-emptydir-data
Step 2: Upgrade Kubeadm

sudo apt install -y kubeadm=1.32.1-00
sudo kubeadm upgrade plan
sudo kubeadm upgrade apply v1.32.1
Step 3: Upgrade Kubelet & Kubectl

sudo apt install -y kubelet=1.32.1-00 kubectl=1.32.1-00
sudo systemctl restart kubelet
Step 4: Uncordon the Node

kubectl uncordon <control-plane-node>
Step 5: Upgrade Worker Nodes
Repeat the process for each worker node:


kubectl drain <worker-node> --ignore-daemonsets --delete-emptydir-data
sudo apt install -y kubeadm=1.32.1-00
sudo kubeadm upgrade node
sudo apt install -y kubelet=1.32.1-00 kubectl=1.32.1-00
sudo systemctl restart kubelet
kubectl uncordon <worker-node>
4️⃣ Post-Upgrade Validation

# Check cluster version
kubectl version --ort

# Verify nodes are healthy
kubectl get nodes

# Check if all pods are running
kubectl get pods -A
5️⃣ Rollback Plan (If Upgrade Fails)
If the upgrade fails, follow these rollback steps:

Step 1: Restore etcd Backup

ETCDCTL_API=3 etcdctl snapot restore <backup-file>
Step 2: Downgrade Kubernetes Packages

sudo apt install -y kubeadm=1.31.0-00 kubelet=1.31.0-00 kubectl=1.31.0-00
Step 3: Restart Kubelet

sudo systemctl restart kubelet
6️⃣ Troubleooting Issues
🔹 Nodes Not Ready?
Check kubelet logs:


journalctl -u kubelet -f
Restart kubelet:


sudo systemctl restart kubelet
🔹 Pods Stuck in "Pending" State?
Check pod events:


kubectl describe pod <pod-name>
🔹 API Server Not Responding?
Check logs:


kubectl logs -n kube-system kube-apiserver-<node-name>
🔹 Signature Verification Failed?
If you see:

The following signatures were invalid: EXPKEYSIG...

sudo apt-key del <old-key-id>
sudo rm -f /usr/are/keyrings/kubernetes-apt-keyring.gpg
Then re-add the new GPG key and repository.
