#!/bin/bash
set -e

echo "Starting Minikube..."
minikube start
eval $(minikube docker-env)

# === Build images ===
docker build -t key-registry -f immerse-issuer/Dockerfile.registry .
docker build -t vc-issuer-image -f immerse-issuer/Dockerfile.issuer .
docker build -t verifier-image -f immerse-verifier/Dockerfile.verifier .

# === Apply secrets and deployments ===
kubectl apply -f immerse-issuer/issuer-secret.yaml
kubectl apply -f immerse-verifier/verifier-secret.yaml
kubectl apply -f immerse-issuer/deployment-registry.yaml
kubectl apply -f immerse-issuer/service-registry.yaml

kubectl apply -f immerse-issuer/deployment-issuer.yaml
kubectl apply -f immerse-issuer/service-issuer.yaml

echo "Waiting for issuer pods to be ready..."
kubectl wait --for=condition=ready pod -l app=vc-issuer --timeout=120s
kubectl wait --for=condition=ready pod -l app=key-registry --timeout=60s

# === Start Ngrok with both tunnels ===
echo "Starting Ngrok..."
ngrok start --all > ngrok.log &
NGROK_PID=$!
sleep 10

# Get URLs with retry logic
for i in {1..5}; do
  ISSUER_URL=$(curl -s localhost:4040/api/tunnels | jq -r '.tunnels[] | select(.name == "issuer") | .public_url')
  VERIFIER_URL=$(curl -s localhost:4040/api/tunnels | jq -r '.tunnels[] | select(.name == "verifier") | .public_url')
  
  if [ -n "$ISSUER_URL" ] && [ -n "$VERIFIER_URL" ]; then
    break
  fi
  echo "Waiting for Ngrok URLs to be available (attempt $i)..."
  sleep 5
done

echo "Issuer Ngrok URL: $ISSUER_URL"
echo "Verifier Ngrok URL: $VERIFIER_URL"

# Update issuer 
echo "Updating issuer configuration..."
kubectl set env deployment/vc-issuer ISSUER_BASE_URL=$ISSUER_URL

# Wait a bit before restarting
sleep 10

# Rollout restart
kubectl rollout restart deployment/vc-issuer

# Wait for rollout to complete
if ! kubectl rollout status deployment/vc-issuer --timeout=120s; then
  echo "Issuer rollout failed, checking status..."
  kubectl get pods -l app=vc-issuer
  kubectl describe deployment vc-issuer
  echo "Trying to continue with verifier deployment..."
fi

# Deploy verifier
kubectl apply -f immerse-verifier/deployment-verifier.yaml
kubectl apply -f immerse-verifier/service-verifier.yaml

echo "Waiting for verifier to be ready..."
kubectl wait --for=condition=ready pod -l app=verifier --timeout=120s

# Update verifier
kubectl set env deployment/verifier VERIFIER_BASE_URL=$VERIFIER_URL
sleep 10
kubectl rollout restart deployment/verifier

# Wait for verifier rollout
if ! kubectl rollout status deployment/verifier --timeout=120s; then
  echo "Verifier rollout failed, checking status..."
  kubectl get pods -l app=verifier
  kubectl describe deployment verifier
fi

# === Port forward ===
echo "Starting port forwarding..."
kubectl port-forward service/vc-issuer 3000:80 > /dev/null &
PF_ISSUER=$!
sleep 5

kubectl port-forward service/verifier 32000:80 > /dev/null &
PF_VERIFIER=$!
sleep 5

# === Trap ===
cleanup() {
  echo "Cleaning up..."
  kill $NGROK_PID $PF_ISSUER $PF_VERIFIER 2>/dev/null || true
  echo "Cleaned up all services"
}
trap cleanup EXIT

# === Done ===
echo "=== Deployment Complete ==="
echo "Issuer: $ISSUER_URL"
echo "Verifier: $VERIFIER_URL"
echo ""
echo "Press Ctrl+C to stop everything"
wait

