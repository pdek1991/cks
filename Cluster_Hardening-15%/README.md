# Kubernetes Cluster Hardening & Upgrade Guide

## 🔹 Cluster Hardening

### 🔹 Use Role-Based Access Controls to Minimize Exposure

| Best Practice | Description |
|--------------|-------------|
| ✅ Use Role Instead of ClusterRole Whenever Possible | Limit permissions to a specific namespace. |
| ✅ Restrict Service Accounts with Least Privilege | Avoid granting unnecessary permissions. |
| ✅ Disable Auto-Mounting of Service Account Tokens | Prevent automatic service account token mounting. |
| ✅ Enforce Read-Only Access for Non-Privileged Users | Limit modifications by non-privileged users. |
| ✅ Regularly Audit and Review RBAC Permissions | Periodically verify RBAC settings. |

### 🔹 Service Account Best Practices

| Best Practice | Description |
|--------------|-------------|
| ✅ Rotate Service Account Tokens | Ensure tokens are changed periodically. |
| ✅ Disable Default Service Account | Avoid using default service accounts in namespaces. |
| ✅ Minimize Permissions for Service Accounts | Assign minimal permissions required. |
| ✅ Audit Service Account Usage | Regularly check service account usage. |
| ✅ Service Account Token Path | Tokens are mounted at `/var/run/secrets/kubernetes.io/serviceaccount/`. |
| ✅ Disable Auto-Mounting of Service Accounts | Can be disabled at both service account and pod levels. |
| ✅ Use Custom Service Accounts | Avoid using the default service account. |

### 🔹 Restrict Access to Kubernetes API

1. Use RBAC to restrict API access.
2. Restrict API access with Network Policies.
3. Implement API Server Admission Controllers.
4. Enable NodeRestriction to prevent impersonation.
5. Restrict API access using authentication & authorization.
6. Disable anonymous and unauthorized access.
7. Use firewall rules to restrict API server access.
8. Implement Mutual TLS (mTLS) for secure API communication.
9. Disable service account token auto-mounting.
10. Restrict API access using Pod Security Policies.
11. Monitor API access using audit logging.

---

## 🔹 Upgrading Kubernetes to v1.32

### ✅ Steps for Kubernetes Upgrade

1️⃣ **Updating Kubernetes Repository & GPG Key**

#### Step 1: Remove Old Kubernetes Repository & GPG Key
```sh
sudo rm -f /etc/apt/sources.list.d/kubernetes.list
sudo apt-key del <old-key-id>
sudo rm -f /etc/apt/keyrings/kubernetes-apt-keyring.gpg
```

#### Step 2: Add the Latest Kubernetes Repository
```sh
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.32/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.32/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list
```

#### Step 3: Update & Install Kubernetes Packages
```sh
sudo apt update
sudo apt install -y kubeadm kubelet kubectl
sudo apt-mark hold kubeadm kubelet kubectl  # Prevent automatic upgrades
```

---

2️⃣ **Best Practices for Kubernetes Upgrade**

| Component | Allowed Version Skew | Example |
|-----------|----------------------|---------|
| Kubeadm | +1 version | v1.32 Kubeadm with v1.31 Control Plane |
| Kubelet | -1 version | v1.32 Control Plane with v1.31 Kubelet |
| Kubectl | Exact Match | v1.32 Control Plane with v1.32 Kubectl |

---

3️⃣ **Upgrading Kubernetes Cluster**

#### Step 1: Drain the Control Plane Node
```sh
kubectl drain <control-plane-node> --ignore-daemonsets --delete-emptydir-data
```

#### Step 2: Upgrade Kubeadm
```sh
sudo apt install -y kubeadm=1.32.1-00
sudo kubeadm upgrade plan
sudo kubeadm upgrade apply v1.32.1
```

#### Step 3: Upgrade Kubelet & Kubectl
```sh
sudo apt install -y kubelet=1.32.1-00 kubectl=1.32.1-00
sudo systemctl restart kubelet
```

#### Step 4: Uncordon the Node
```sh
kubectl uncordon <control-plane-node>
```

#### Step 5: Upgrade Worker Nodes (Repeat for Each Worker Node)
```sh
kubectl drain <worker-node> --ignore-daemonsets --delete-emptydir-data
sudo apt install -y kubeadm=1.32.1-00
sudo kubeadm upgrade node
sudo apt install -y kubelet=1.32.1-00 kubectl=1.32.1-00
sudo systemctl restart kubelet
kubectl uncordon <worker-node>
```

---

4️⃣ **Post-Upgrade Validation**
```sh
kubectl version --short
kubectl get nodes
kubectl get pods -A
```

---

5️⃣ **Rollback Plan (If Upgrade Fails)**

#### Step 1: Restore etcd Backup
```sh
ETCDCTL_API=3 etcdctl snapshot restore <backup-file>
```

#### Step 2: Downgrade Kubernetes Packages
```sh
sudo apt install -y kubeadm=1.31.0-00 kubelet=1.31.0-00 kubectl=1.31.0-00
```

#### Step 3: Restart Kubelet
```sh
sudo systemctl restart kubelet
```

---

6️⃣ **Troubleshooting Issues**

🔹 **Nodes Not Ready?**
```sh
journalctl -u kubelet -f
sudo systemctl restart kubelet
```

🔹 **Pods Stuck in 'Pending' State?**
```sh
kubectl describe pod <pod-name>
```

🔹 **API Server Not Responding?**
```sh
kubectl logs -n kube-system kube-apiserver-<node-name>
```

🔹 **Signature Verification Failed?**
If you see:
```
The following signatures were invalid: EXPKEYSIG...
```
Fix:
```sh
sudo apt-key del <old-key-id>
sudo rm -f /etc/apt/keyrings/kubernetes-apt-keyring.gpg
```
Then re-add the new GPG key and repository as shown in Step 2 above.

