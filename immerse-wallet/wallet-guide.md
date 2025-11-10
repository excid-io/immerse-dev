# IMMERSE Wallet Deployment Guide

## Overview

This guide explains how to deploy the IMMERSE Wallet in a local or remote CVM for the first time and how to restart it safely in subsequent sessions.
Pre-requisites: kubectl, minikube, docker, and kubeseal installed.

## First time setup

1. Start Minikube and Create Namespaces:

```bash
minikube start --cni=cilium
kubectl create namespace cvm-security
kubectl create namespace cvm-wallets
minikube addons enable metrics-server
```

Optional flags for minikube start `--driver=docker --cpus=4 --memory=6g`. You can also make sure minikube started successfully with a kubectl command, e.g. `kubectl get nodes`. Namespaces separate security components (attestation service, SoftHSM) from wallet components (frontend, gateway, backend).
Optionally, you can also enable the Kubernetes metrics-server, which provides resource usage data (CPU, memory) for pods and nodes. This is required for commands, such as kubectl top and for testing autoscaling or monitoring resource consumption during the attestation service and wallet workflows. Note that this logic is not provided in the current format of this repository.

2. Install Bitnami Sealed Secrets

```bash
kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.27.2/controller.yaml
kubectl -n kube-system rollout status deploy/sealed-secrets-controller
```

Create and seal the SoftHSM PINs:

```bash
kubectl -n cvm-security create secret generic softhsm-pins \
  --from-literal=PIN=1234 --from-literal=SO_PIN=1234 \
  --dry-run=client -o yaml > softhsm-pins.secret.yaml

kubeseal --format=yaml < softhsm-pins.secret.yaml > softhsm-pins.sealed.yaml
kubectl apply -f softhsm-pins.sealed.yaml
```

Replace "1234" with your own chosen `PIN` and `SO_PIN` values, "1234" is an example value. These should be unique per deployment.
Delete softhsm-pins.secret.yaml after sealing.

3. Initialize SoftHSM Token
Apply the persistent volume and initialization job:

```bash
kubectl apply -f softhsm-pvc.yaml
kubectl apply -f softhsm-init-token.yaml
kubectl -n cvm-security logs job/softhsm-init
```

This step creates persistent token storage and an IMMERSE token with the A-Key.

4. Deploy Attestation Service
Create RBAC for TokenReview:

```bash
kubectl apply -f attester-rbac.yaml
```

Build and deploy the attester image:

```bash
eval $(minikube docker-env)
cd ~/attester
docker build -f Dockerfile.attester -t cvm-attester:local .
cd ..
kubectl apply -f cvm-attester.yaml
kubectl -n cvm-security rollout restart deploy/cvm-attester
kubectl -n cvm-security rollout status deploy/cvm-attester
```

Apply the network policy to restrict access:

```bash
kubectl label namespace cvm-wallets name=cvm-wallets --overwrite
kubectl apply -f attester-netpol.yaml
```

first command is to make sure the wallets namespace has the label your policy expects.
The aim is to ensure only pods in cvm-wallets can reach the Attester on port 5000, all others are blocked.

5. Build and Deploy the Wallet
Build Docker images for backend and frontend:

```bash
cd ~/immerse-wallet
eval $(minikube docker-env)
docker build -t wallet-backend:local  -f Dockerfile.backend .
docker build -t wallet-frontend:local -f Dockerfile.frontend .
```

Deploy the wallet services:

```bash
kubectl apply -f wallet-sa.yaml
kubectl apply -f wallet-backend.yaml
kubectl apply -f wallet-frontend.yaml
```

Expose the frontend:

```bash
kubectl -n cvm-wallets port-forward svc/wallet-frontend 30080:8080 --address=0.0.0.0 &
echo $! > /tmp/pf-frontend.pid
```

To make it externally available use self signed certificates or e.g. through ngrok, read the instructions and run `ngrok http CVM_IP:30080`, or install ngrok in your CVM and run the appropriate command.
Remember to disengage minikube's docker daemon and stop and delete the minikube cluster if you don't need them anymore.

## Subsequent setup

If the cluster already exists and secrets/volumes are initialized, you do not need to repeat Sealed Secrets or SoftHSM setup.

1. Start the Cluster

```bash
minikube start --cni=cilium
```

2. Load Images and Restart Deployments

Rebuild (if you changed code) or reuse existing images:

```bash
eval $(minikube docker-env)
docker build -t wallet-backend:local  -f Dockerfile.backend .
docker build -t wallet-frontend:local -f Dockerfile.frontend .
docker build -t cvm-attester:local    -f Dockerfile.attester .
```

Restart deployments:

```bash
kubectl -n cvm-security rollout restart deploy/cvm-attester
kubectl -n cvm-wallets  rollout restart deploy/wallet-backend
kubectl -n cvm-wallets  rollout restart deploy/wallet-frontend
```

3. Verify Connectivity

Confirm all pods are healthy:

```bash
kubectl get pods -A
```


Confirm NetworkPolicy enforcement:

```bash
kubectl -n cvm-wallets run test --image=curlimages/curl:8.10.1 -- curl -i http://cvm-attester.cvm-security.svc.cluster.local:5000/attest
```

If you see `401 missing_bearer_token`, the connection path is correct and the Attester is enforcing authentication. This is the expected response when no JWT is provided. Messages indicating an issue with NetworkPolicy would include Connection refused (service not running or blocked), Could not resolve host (DNS/namespace issue), or 404 Not Found (wrong endpoint). These indicate connectivity or configuration problems rather than healthy enforcement.

4. Access the Wallet Frontend

Port-forward or use ngrok again:

```bash
kubectl -n cvm-wallets port-forward svc/wallet-frontend 30080:8080 --address=0.0.0.0 &
ngrok http 10.0.12.40:30080
```

Visit the printed URL and proceed with credential issuance or verification.

## Maintenance Tips

Key persistence: The SoftHSM PVC (softhsm-pvc) retains your A-Key across restarts; only delete it if you intentionally rotate the attestation root.

Cluster cleanup:

```bash
minikube stop
minikube delete
docker system prune -a
```

Debug logs:
Use `kubectl logs -n cvm-security deploy/cvm-attester` for the attestation service or `kubectl logs -n cvm-wallets deploy/wallet-backend` for the backend.
