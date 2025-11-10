#!/bin/bash
set -e

echo "Reverting Docker env..."
eval $(minikube docker-env -u)

echo "Deleting Kubernetes resources..."
kubectl delete -f immerse-issuer/deployment-issuer.yaml --ignore-not-found
kubectl delete -f immerse-issuer/service-issuer.yaml --ignore-not-found
kubectl delete -f immerse-verifier/deployment-verifier.yaml --ignore-not-found
kubectl delete -f immerse-verifier/service-verifier.yaml --ignore-not-found
kubectl delete -f immerse-issuer/deployment-registry.yaml --ignore-not-found
kubectl delete -f immerse-issuer/service-registry.yaml --ignore-not-found
kubectl delete secret issuer-secrets --ignore-not-found
kubectl delete secret verifier-secrets --ignore-not-found

echo "Stopping ngrok..."
pkill ngrok || true

echo "Stopping and deleting Minikube..."
minikube stop
minikube delete

echo "Cleanup complete!"

