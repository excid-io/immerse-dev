# Latency and Performance Measurements of the IMMERSE Ecosystem

## Overview

This section includes all timing measurements that capture the end-to-end performance of the verifiable credential lifecycle in the IMMERSE ecosystem across four main phases:

1. Attestation: Wallet obtains attestation from the CVM attester
2. Token Retrieval: Wallet receives an access token from the issuer
3. Credential Issuance: Wallet receives the SD-JWT VC from the issuer
4. Presentation: Wallet creates and submits a VP to the verifier

Each measurement reflects the Round-Trip Time (RTT) experienced by the wallet during the credential lifecycle, meaning the elapsed time from when the wallet issues a request until the corresponding response is received. In our context, RTT does not only capture the component's internal processing, but also the network latency, Kubernetes routing, and orchestration overhead, making it the most accurate indicator of end-to-end client-perceived delay. Across the experiment we recorded 14 complete runs of the full lifecycle and observed consistent performance across all runs. The table below reports the averages for each phase, as well as the server-side processing times and descriptions:

| Component                | Metric                          | Value (ms) | Notes                                                        |
| ------------------------ | ------------------------------- | ----------- | ------------------------------------------------------------|
| **Wallet**               | `t_attest_res - t_attest_req`   |      **45** | Attestation RTT (wallet -> attester -> wallet)              |
|                          | `t_token_res - t_token_req`     |     **158** | Token request RTT to issuer `/token`                        |
|                          | `t_issue_res - t_issue_req`     |     **131** | Issuance RTT to issuer `/credential`                        |
|                          | `t_vp_pop_sign`                 |       **2** | Wallet PoP signing time for VP                              |
|                          | `t_present_res - t_present_req` |     **662** | Presentation POST to verifier until response                |
| **Attester**             | `tokenreview`                   |      **19** | Kubernetes TokenReview latency                              |
|                          | `sign`                          |      **11** | SoftHSM/PKCS#11 signing latency                             |
|                          | `end total`                     |      **30** | Total attester processing (TokenReview + sign + overhead)   |
| **Issuer (/token)**      | `pop_verify`                    |       **4** | Verify PoP + claims                                         |
|                          | `token_issued` (total)          |       **6** | Total `/token` handling (recv -> issue)                     |
| **Issuer (/credential)** | `proof_verify`                  |       **4** | Verify OID4VCI proof JWT                                    |
|                          | `vc_sign`                       |       **4** | SD-JWT-VC signing                                           |
|                          | `issue_done` (total)            |      **16** | Total issuance handling (recv -> respond)                   |
| **Verifier**             | `vp_verify`                     |       **7** | Verify VP JWT                                               |
|                          | `revoc_check`                   |     **197** | Status list fetch & check                                   |
|                          | `verified_out` (total)          |     **514** | Total verifier processing                                   |

The revocation check time of approx. 197ms represents a significant portion of the total verifier processing time. To investigate this further, we conducted additional analysis outside the original 14 measurement runs, by first identifying whether the revocation check was affected by HTTP request overhead:

```bash
kubectl logs deploy/verifier | grep 'axios_request'
```

where the output `axios_request: 209.743ms` confirmed this. We then performed comparative testing to isolate the source of latency. Internal service calls within the same Kubernetes cluster demonstrated optimal performance:

```bash
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl -w "Time: %{time_total}s\n" http://vc-issuer/.well-known/credential-status.json
```

with output `Time: 0.003827s`, i.e. 3.8ms. However, detailed analysis of external calls through our ngrok tunneling revealed substantial overhead. Specifically, to precisely identify the source of revocation check latency, we used curl's detailed timing capabilities:

```bash
kubectl run -it --rm debug --image=curlimages/curl --restart=Never -- \
  curl -w "
    DNS Lookup: %{time_namelookup}s
    TCP Connect: %{time_connect}s  
    TLS Handshake: %{time_appconnect}s
    Pre-transfer: %{time_pretransfer}s
    Redirect: %{time_redirect}s
    First Byte: %{time_starttransfer}s
    Total: %{time_total}s
  " -o /dev/null -s "https://${EXTERNAL_ISSUER_URL}$/.well-known/credential-status.json"
```

This command creates a temporary Kubernetes pod with curl to test network timing, uses curl's `-w` (write-out) flag to output specific timing metrics and `-o /dev/null -s` discards the response body and suppresses output noise. The results where:

```bash
DNS Lookup: 0.068807s
TCP Connect: 0.106280s  
TLS Handshake: 0.154602s
Pre-transfer: 0.154721s
Redirect: 0.000000s
First Byte: 0.247151s
Total: 0.247290s
```

The curl command used specific timing variables to break down the HTTP request lifecycle: %{time_namelookup} measures DNS resolution time (converting hostname to IP), %{time_connect} captures TCP handshake duration, %{time_appconnect} tracks TLS/SSL negotiation time, %{time_starttransfer} shows Time to First Byte (server processing + initial response), and %{time_total} provides the complete request duration. The results reveal a clear performance profile: 69ms for DNS lookup, 37ms for TCP connection establishment (excl. DNS), 48ms for TLS handshake (excluding TCP Connect and DNS), and 93ms for server processing and response transfer, totaling 247ms. This breakdown demonstrates that majority of the time (154ms) is spent purely on connection setup before any application logic begins, while the remaining time represents actual processing and data transfer, confirming that the latency is primarily infrastructure-related rather than application-bound.

Despite both issuer and verifier running in the same development cluster (and node) for convenience in the development and testing phases of the IMMERSE project, we deliberately maintain the external URL configuration for revocation checks to better simulate production environments. In real-world deployments issuers and verifiers typically operate in separate trust domains, thus verifiers must use the issuer's public endpoints for revocation status. The measured 197ms, while higher than ideal, reflects realistic cross-network latency. Production environments with direct cloud-to-cloud connectivity would likely achieve 50-80ms for similar checks. This approach ensures our performance measurements remain relevant for production scenarios, while acknowledging the development environment overhead.

