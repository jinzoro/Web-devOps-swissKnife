
# Scope & philosophy

* **Everything you routinely need**: Linux admin, storage, processes, services, users, packaging, logs, SELinux/AppArmor, firewalls, Docker/Podman/K8s, network tooling, performance, backups, **SSL/TLS from A→Z** (keys, CSRs, certs, chains, keystores, OCSP, HSTS), Git/CI, cloud CLIs.
* **Three execution modes**

  1. **WASM (client)**: safe tools like `jq`, `yq`, text filters, JSON/YAML, base64, regex, parsers.
  2. **Remote runner** (K8s Job; allowlisted commands; read-only by default).
  3. **Local agent** (optional) for on-prem power, still allowlisted.
* **Everything is schema-driven**: every action has a JSON-Schema to validate parameters; the UI autogenerates forms; templates render commands safely.

---

# Feature map (what the app ships with)

## A) Systems engineer toolbox

**Core OS & services**

* Users & auth: `id`, `who`, `last`, `passwd`, `useradd/usermod/userdel`, `groupadd/usermod`, `chage`, `loginctl`
* Processes: `ps`, `top/htop/atop`, `nice/renice`, `kill/killall`, `pmap`, `lsof`
* Services: `systemctl` (status/start/stop/restart/enable/disable), `journalctl` (follow/filters)
* Packages:

  * **Fedora/RHEL**: `dnf/yum`, `rpm`
  * **Debian/Ubuntu**: `apt/apt-get`, `dpkg`
  * **Arch**: `pacman`
  * **SUSE**: `zypper`
  * **Containers**: `flatpak`, `snap`
* Filesystems & storage: `lsblk`, `blkid`, `mount/umount`, `findmnt`, `df/du`, `parted`, `fdisk/sfdisk`, `mkfs.*`, `tune2fs`
* LVM/RAID/ZFS/Btrfs:

  * LVM: `pvcreate/pvs`, `vgcreate/vgs`, `lvcreate/lvs`, `lvextend`, `vgextend`, `pvmove`, `fsadm`
  * RAID: `mdadm`
  * ZFS: `zpool`, `zfs`
  * Btrfs: `btrfs subvolume/snapshot/send/receive/balance`
* Performance & IO:

  * CPU/mem: `free`, `vmstat`, `sar`, `mpstat`
  * Disk: `iostat`, `iotop`, `fio`, `smartctl`
* Logs & auditing: `journalctl`, `/var/log/*`, `ausearch/auditctl` (Auditing)
* Security:

  * **SELinux**: `getenforce/setenforce`, `semanage`, `restorecon`
  * **AppArmor**: `aa-status/enforce/complain`
  * **Firewalls**: `firewalld` (`firewall-cmd`), `nft`, `iptables` (legacy), `ufw`
* Scheduling & timers: `crontab`, `systemd-run`, `systemd timers`
* Archiving & data: `tar`, `rsync`, `gzip/xz/zstd`, `rclone`
* Text & data wrangling: `grep`, `ripgrep (rg)`, `awk`, `sed`, `cut/sort/uniq/comm`, `tr`, `xargs`, `paste`, `diff`, `patch`, `jq`, `yq`

**Containers & orchestration**

* Docker/Podman: `ps`, `logs`, `top`, `exec`, `inspect`, `events`, `cp`, `stats`, `compose`
* Kubernetes: `kubectl get/describe/logs/exec/port-forward/cp/events`, `kubectl auth can-i`, `kubectl top`, `kubectl debug`, contexts/namespaces
* Helm: `repo add/update`, `search`, `install/upgrade/uninstall`, `history`, `rollback`
* Terraform: `fmt/validate/plan/apply/destroy`, backends, workspaces (dry-run first policy)
* Ansible: `ansible -m ping`, `ansible-playbook --check --diff`, inventories, vault

**Git & CI**

* Git: branch/merge/rebase/cherry-pick/stash/bisect, GPG signing, sparse checkout
* Release helpers: changelog from commits, conventional commits checker
* CI recipes: GH Actions scaffolds for Docker build, Helm chart package, Terraform plan

## B) Network engineer toolbox

* Interfaces & IP: `ip a/r/route`, `ss` (sockets), `ethtool`, `nmcli`, `iw`, `iwconfig`
* Name resolution & DNS: `dig`, `drill`, `host`, `nslookup`, zone transfers (safe mode), DNSSEC checks
* Connectivity & paths: `ping/ping6`, `traceroute/mtr`, `tracepath`
* Capture & analysis: `tcpdump` filters, `tshark` basics
* Scanning & testing: `nmap` (safe presets), `nc/socat`, `iperf3`
* VPN & tunnels (read-only info by default): `wg`, `wg-quick`, `openvpn --show-*`
* HTTP/S checks: `curl` (headers, TLS, HTTP/2), `wget`
* Routing & NAT:

  * Modern: `nft list ruleset`, add/remove (editor guarded)
  * Legacy: `iptables -S` (read-only), `ip rule/table` for policy routing

## C) SSL/TLS/PKI end-to-end

Everything a sys/net/DevOps engineer needs to **create, convert, inspect, validate, deploy** certs:

**Key generation & CSRs**

* `openssl genrsa` / `openssl genpkey -algorithm RSA|EC`
* `openssl req -new -key … -subj … -config …` (SANs via `req_ext`)
* Strong defaults (RSA 2048/4096, P-256/P-384 EC), entropy checks

**Certificate formats & conversions**

* PEM/DER ↔ `openssl x509 -in … -inform …`
* PKCS#12: `openssl pkcs12 -export` (with CA chain & key)
* Java keystores: `keytool -importkeystore`, PEM↔JKS/PKCS12
* Nginx/Apache bundles: correct **order** (leaf → intermediates → root (optional))

**Validation & inspection**

* `openssl x509 -noout -text -in cert.pem`
* Chain build & verify: `openssl verify -CAfile chain.pem cert.pem`
* Hostname & expiry check: `openssl s_client -connect host:443 -servername host -showcerts`
* OCSP: `openssl ocsp -issuer intermediate.pem -cert cert.pem -url http://ocsp…` (or AIA auto)
* CRL: `openssl crl -in crl.pem -noout -text`
* HSTS & protocols: `curl -I https://host`, ALPN/HTTP2; `nmap --script ssl-enum-ciphers -p 443 host` (read-only)
* CT logs quick look: (script hitting crt.sh APIs **off by default** unless you wire a backend fetcher)

**Automation (ACME)**

* `certbot` (webroot/dns), `acme.sh` (DNS providers), renew hooks
* Staging vs prod endpoints, rate-limit awareness
* Post-issuance deploy hooks: copy to `/etc/…`, reload service, permissions

**Keystore ecosystem**

* Tomcat/Jetty: PKCS12 to JKS, `server.xml` connector hints
* Kafka/ELK/Java apps: truststore/keystore separation, alias handling
* Windows/IIS (optional docs): `Import-PfxCertificate`

**Best-practice linting**

* Key size, signature alg, SAN presence, EKU, validity period, AIA/OCSP URLs, chain order
* Simple linter in the app (WASM parse + rules) before deployment

---

# App architecture (unchanged core + extended libraries)

* **Frontend**: Next.js (TS), Tailwind, shadcn/ui, Zustand, xterm.js, PWA.
* **WASM tools**: `jq`, `yq`, `ripgrep`, `busybox` (sed/awk/tar/sha1/sha256/base64), PEM parser, simple X.509 parser for lint.
* **Backend**: FastAPI or Go; Postgres; K8s Job runner; RBAC; NetworkPolicies; secret redaction.
* **Libraries**: huge **Action Library** (read-only by default). Mutating actions are guarded by role + “dry-run first”.

---

# Action library (seed content)

Below are **representative** actions you can paste into your `packages/schemas` and expand. (All have read-only variants first.)

## 1) Systems – Services & logs

**system.service.status**

```json
{
  "key": "system.service.status",
  "cmd": "systemctl status {{service}} --no-pager",
  "read_only": true,
  "timeout_s": 20,
  "schema": {
    "properties": {
      "service": { "pattern": "^[a-zA-Z0-9@._-]{1,128}$" }
    },
    "required": ["service"],
    "additionalProperties": false
  }
}
```

**system.journal.tail**

```json
{
  "key": "system.journal.tail",
  "cmd": "journalctl -u {{service}} -n {{lines}} -o short-iso -f",
  "read_only": true,
  "timeout_s": 120,
  "schema": {
    "properties": {
      "service": { "pattern": "^[a-zA-Z0-9@._-]{1,128}$" },
      "lines": { "type": "integer", "minimum": 10, "maximum": 5000 }
    },
    "required": ["service","lines"],
    "additionalProperties": false
  }
}
```

**system.service.restart** (mutating; role: editor+)

```json
{
  "key": "system.service.restart",
  "cmd": "systemctl restart {{service}}",
  "read_only": false,
  "timeout_s": 30,
  "role": "editor",
  "schema": {
    "properties": { "service": { "pattern": "^[a-zA-Z0-9@._-]{1,128}$" } },
    "required": ["service"], "additionalProperties": false
  }
}
```

## 2) Systems – Packages (Fedora/Debian)

**pkg.search**

```json
{
  "key": "pkg.search",
  "cmd": "{{manager}} search {{query}}",
  "read_only": true,
  "schema": {
    "properties": {
      "manager": { "enum": ["dnf","apt","zypper","pacman"] },
      "query": { "pattern": "^[a-zA-Z0-9.+_-]{1,64}$" }
    },
    "required": ["manager","query"], "additionalProperties": false
  }
}
```

**pkg.install** (mutating; dry-run if supported)

```json
{
  "key": "pkg.install",
  "cmd": "{{manager}} {{sub}} {{name}}",
  "read_only": false,
  "role": "editor",
  "schema": {
    "properties": {
      "manager": { "enum": ["dnf","apt"] },
      "sub": { "enum": ["install","--assumeno install","--simulate install"] },
      "name": { "pattern": "^[a-zA-Z0-9.+_-]{1,64}$" }
    },
    "required": ["manager","sub","name"],
    "additionalProperties": false
  }
}
```

## 3) Storage

**storage.lvm.lvextend**

```json
{
  "key": "storage.lvm.lvextend",
  "cmd": "lvextend -r -L +{{size}} {{lv}}",
  "read_only": false,
  "role": "editor",
  "schema": {
    "properties": {
      "size": { "pattern": "^[0-9]+(G|M)$" },
      "lv": { "pattern": "^/dev/[a-zA-Z0-9_/-]+$" }
    },
    "required": ["size","lv"], "additionalProperties": false
  }
}
```

## 4) Networking

**net.interfaces**

```json
{
  "key": "net.interfaces",
  "cmd": "ip -br a",
  "read_only": true, "timeout_s": 10, "schema": { "type": "object", "properties": {} }
}
```

**net.tcpdump** (read-only capture with filters)

```json
{
  "key": "net.tcpdump",
  "cmd": "tcpdump -nn -c {{count}} -i {{iface}} {{filter}}",
  "read_only": true,
  "timeout_s": 60,
  "schema": {
    "properties": {
      "iface": { "pattern": "^[a-zA-Z0-9._-]{1,32}$" },
      "count": { "type": "integer", "minimum": 1, "maximum": 1000 },
      "filter": { "pattern": "^[\\w\\s.:/()*-]*$" }
    },
    "required": ["iface","count"], "additionalProperties": false
  }
}
```

**net.dns.lookup**

```json
{
  "key": "net.dns.lookup",
  "cmd": "dig +nocmd {{name}} {{type}} +noall +answer",
  "read_only": true,
  "schema": {
    "properties": {
      "name": { "pattern": "^[a-zA-Z0-9.-]{1,253}$" },
      "type": { "enum": ["A","AAAA","CNAME","MX","TXT","NS","SOA","CAA","SRV"] }
    },
    "required": ["name","type"], "additionalProperties": false
  }
}
```

**net.http.check**

```json
{
  "key": "net.http.check",
  "cmd": "curl -s -o /dev/null -w 'code=%{http_code} tls=%{ssl_verify_result} proto=%{http_version}\\n' --resolve {{host}}:{{port}}:{{ip}} https://{{host}}:{{port}}/",
  "read_only": true,
  "schema": {
    "properties": {
      "host": { "pattern": "^[a-zA-Z0-9.-]{1,253}$" },
      "ip": { "pattern": "^(\\d{1,3}\\.){3}\\d{1,3}$" },
      "port": { "type": "integer", "minimum": 1, "maximum": 65535 }
    },
    "required": ["host","ip","port"], "additionalProperties": false
  }
}
```

## 5) SSL/TLS/PKI

**ssl.key.gen**

```json
{
  "key": "ssl.key.gen",
  "cmd": "openssl genpkey -algorithm {{algo}} {{params}} -out {{out}}",
  "read_only": false,
  "role": "editor",
  "schema": {
    "properties": {
      "algo": { "enum": ["RSA","EC"] },
      "params": { "enum": ["-pkeyopt rsa_keygen_bits:2048","-pkeyopt rsa_keygen_bits:4096","-pkeyopt ec_paramgen_curve:P-256","-pkeyopt ec_paramgen_curve:P-384"] },
      "out": { "pattern": "^[a-zA-Z0-9._/-]{1,120}$" }
    },
    "required": ["algo","params","out"], "additionalProperties": false
  }
}
```

**ssl.csr.create**

```json
{
  "key": "ssl.csr.create",
  "cmd": "openssl req -new -key {{key}} -out {{csr}} -subj '{{subj}}' -config {{cnf}} -reqexts req_ext",
  "read_only": false,
  "role": "editor",
  "schema": {
    "properties": {
      "key": { "pattern": "^[a-zA-Z0-9._/-]{1,120}$" },
      "csr": { "pattern": "^[a-zA-Z0-9._/-]{1,120}$" },
      "subj": { "pattern": "^/C=[A-Z]{2}/ST=[^/]{1,64}/O=[^/]{1,64}/CN=[^/]{1,64}$" },
      "cnf": { "pattern": "^[a-zA-Z0-9._/-]{1,120}$" }
    },
    "required": ["key","csr","subj","cnf"], "additionalProperties": false
  }
}
```

**ssl.cert.inspect**

```json
{
  "key": "ssl.cert.inspect",
  "cmd": "openssl x509 -in {{cert}} -noout -text",
  "read_only": true,
  "schema": { "properties": { "cert": { "pattern": "^[a-zA-Z0-9._/-]{1,120}$" } }, "required": ["cert"] }
}
```

**ssl.chain.verify**

```json
{
  "key": "ssl.chain.verify",
  "cmd": "openssl verify -CAfile {{chain}} {{cert}}",
  "read_only": true,
  "schema": {
    "properties": {
      "chain": { "pattern": "^[a-zA-Z0-9._/-]{1,120}$" },
      "cert": { "pattern": "^[a-zA-Z0-9._/-]{1,120}$" }
    },
    "required": ["chain","cert"], "additionalProperties": false
  }
}
```

**ssl.pkcs12.export**

```json
{
  "key": "ssl.pkcs12.export",
  "cmd": "openssl pkcs12 -export -inkey {{key}} -in {{cert}} -certfile {{chain}} -out {{pfx}}",
  "read_only": false,
  "role": "editor",
  "schema": {
    "properties": {
      "key": { "pattern": "^[a-zA-Z0-9._/-]{1,120}$" },
      "cert": { "pattern": "^[a-zA-Z0-9._/-]{1,120}$" },
      "chain": { "pattern": "^[a-zA-Z0-9._/-]{1,120}$" },
      "pfx": { "pattern": "^[a-zA-Z0-9._/-]{1,120}$" }
    },
    "required": ["key","cert","chain","pfx"], "additionalProperties": false
  }
}
```

**ssl.ocsp.check**

```json
{
  "key": "ssl.ocsp.check",
  "cmd": "openssl ocsp -issuer {{issuer}} -cert {{cert}} -url {{ocsp}} -VAfile {{issuer}} -resp_text -noverify",
  "read_only": true,
  "schema": {
    "properties": {
      "issuer": { "pattern": "^[a-zA-Z0-9._/-]{1,120}$" },
      "cert": { "pattern": "^[a-zA-Z0-9._/-]{1,120}$" },
      "ocsp": { "pattern": "^https?://[^\\s]{1,200}$" }
    },
    "required": ["issuer","cert","ocsp"], "additionalProperties": false
  }
}
```

**ssl.keystore.jks.from.pfx** (Java world)

```json
{
  "key": "ssl.keystore.jks.from.pfx",
  "cmd": "keytool -importkeystore -srckeystore {{pfx}} -srcstoretype PKCS12 -destkeystore {{jks}} -deststoretype JKS -srcalias {{alias}} -destalias {{alias}}",
  "read_only": false,
  "role": "editor",
  "schema": {
    "properties": {
      "pfx": { "pattern": "^[a-zA-Z0-9._/-]{1,120}$" },
      "jks": { "pattern": "^[a-zA-Z0-9._/-]{1,120}$" },
      "alias": { "pattern": "^[a-zA-Z0-9._-]{1,64}$" }
    },
    "required": ["pfx","jks","alias"], "additionalProperties": false
  }
}
```

**ssl.acme.certbot.webroot** (mutating; editor+)

```json
{
  "key": "ssl.acme.certbot.webroot",
  "cmd": "certbot certonly --webroot -w {{webroot}} -d {{domain}} --email {{email}} --agree-tos --non-interactive",
  "read_only": false, "role": "editor",
  "schema": {
    "properties": {
      "webroot": { "pattern": "^/[a-zA-Z0-9._/-]{1,200}$" },
      "domain": { "pattern": "^[a-zA-Z0-9.-]{1,253}$" },
      "email": { "format": "email" }
    },
    "required": ["webroot","domain","email"], "additionalProperties": false
  }
}
```

## 6) Kubernetes & Cloud (read-only first)

* `kube.get`, `kube.describe`, `kube.logs`, `kube.top`, `kube.exec` (guarded), `helm.list/history`
* Cloud CLIs (read-only identities):

  * AWS: `aws sts get-caller-identity`, S3 list (readonly bucket)
  * Azure: `az account show`
  * GCP: `gcloud auth list`

---

# UI modules to surface all this

* **Command Palette**: fuzzy search actions/snippets by tags (system, net, ssl, kube, docker, pkg, dns, tls, lvm, firewall, selinux, etc.).
* **Toolbox tabs**:

  * JSON↔YAML, jq playground, regex tester, base64, URL encode/decode
  * SSL Lab: **Key/CSR wizard**, **Bundle builder**, **Inspector**, **Chain verifier**, **PKCS12/JKS converters**, **OCSP probe**
* **K8s Explorer**: pods/deploys/services/events/logs; right-click → run action.
* **Network Workbench**: DNS lookups, mtr/traceroute, tcpdump live tail (safe limit), iperf test forms.
* **Snippets → Forms**: param schemas render clean forms; “dry-run first” switch.
* **LLM sidekick**: “Explain this command”, “Generate Linux command for ‘X’ with dry-run”.

---

# Security & policy (expanded)

* **Default read-only** for everything; mutating actions require `editor+` role and often enforce **dry-run first**.
* **Redaction**: live redact patterns (private keys, tokens, passwords, PEM blocks unless explicitly requested).
* **Runner**: non-root, `readOnlyRootFilesystem`, seccomp profile, capability drop, NetworkPolicies.
* **Quotas**: per-org rate limits, run timeouts, max log size, concurrent jobs cap.

---

# Seed content index (what you actually ship day-1)

* **System** (40+): service status/restart, journal tail/grep, `top/iostat/iotop`, `free/vmstat`, user add/mod/lock, groups, `passwd --status`, `crontab` list, SELinux get/enforce, `firewall-cmd --list-*`, nft ruleset (read), mount table, `findmnt`, `lsblk -o`, LVM list/extend, mdadm detail, ZFS list/snapshot, Btrfs list/snapshot
* **Packages** (10+): search/install/remove/update (with distro switch + dry-run)
* **Files & data** (15+): `tar` create/extract, `rsync` (archive/dry-run), `grep/awk/sed` presets, hash sum verify
* **Network** (35+): ip addr/route, ss summary, ethtool, nmcli conn, iw scan, ping/mtr/traceroute, dig (A/AAAA/MX/TXT/CAA/SRV/NS/SOA), tcpdump filters (http,dns,tls,host,port), iperf3 client/server, curl TLS info, nmap safe scripts
* **Docker/Podman** (15+): ps/logs/stats/inspect/events/exec (guarded)/compose up -d (guarded)
* **Kubernetes/Helm** (20+): get/describe/logs/top/events/port-forward (guarded), helm list/history/rollback (guarded)
* **Terraform/Ansible** (10+): `terraform fmt/validate/plan`, `apply` (guarded), `ansible -m ping`, `ansible-playbook --check`
* **SSL/TLS/PKI** (25+): key gen, CSR, inspect, verify chain, s\_client fetch, ocsp, crl, pkcs12 export, keytool import, nginx/apache bundle creators, certbot/acme.sh flows, HSTS/ALPN checks, STS header check, cert expiration scanner (for list of hosts)
* **Git** (15+): status/branches/graph/log formatters, rebase helpers, stash, bisect start/good/bad, signed tag

---

# Build & delivery phases (tight)

**Phase 0 – Scaffold (1–2 days)**

* Monorepo, Next.js shell, shadcn, Zustand, PWA, xterm.js; API skeleton; Postgres via docker-compose.
* Roles: owner/admin/editor/viewer.
  **Done when:** palette opens, actions list loads (mock).

**Phase 1 – WASM & Toolbox (3–5 days)**

* `jq/yq/rg/busybox` WASM + worker API.
* JSON↔YAML, jq playground, regex tester, base64 tools.
* SSL **Inspector (WASM)**: parse PEM, show subject/SANs/validity.
  **Done when:** offline tools work; PEMs parse client-side.

**Phase 2 – Runner + Read-only Actions (5–7 days)**

* K8s Job runner, RBAC (read-only), log streaming, redaction.
* Ship **read-only** packs: system/net/docker/kube/ssl verify.
  **Done when:** `kubectl get pods`, `dig A`, `openssl x509 -text` all stream results.

**Phase 3 – Mutating (guarded) (5–7 days)**

* Editor-only: service restart, pkg install (dry-run first), LVM extend, Helm upgrade/rollback, certbot webroot/dns (with prechecks).
* Approvals (optional): require admin click for dangerous ops.
  **Done when:** guarded actions prompt & execute with audit trails.

**Phase 4 – SSL Wizards & Network Workbench (4–6 days)**

* **CSR/Bundle/PKCS12/JKS** wizards (forms + validation)
* Chain verifier with hints; OCSP probe; nginx/apache snippets
* Network panel for tcpdump/mtr/iperf with presets
  **Done when:** you can go from **domain → CSR → issue (sim) → bundle → PFX/JKS → deploy snippet** in one flow.

**Phase 5 – Library Growth & Docs (ongoing)**

* Add 100+ curated snippets and recipes with tags.
* SECURITY.md, runbooks, contribution guide.
* E2E tests (Playwright) for critical flows.

---

# Quality bars & safety rails

* **Dry-run first** toggles whenever available (terraform/ansible/pkg).
* **No secrets in logs**: redact PEM private keys, JWTs, tokens, passwords, kubeconfig.
* **Time limits**: 30–120s per action; cancel support.
* **Backpressure**: limit terminal lines; download full log as artifact if needed.
* **Observability**: traces for action lifecycle, error rates, slow commands.

---

# Want me to generate the repo scaffold?

Say the word with:

* Backend: **FastAPI** or **Go**
* Package manager: **pnpm/yarn/npm**
* Default distro bias for examples: **Fedora** (dnf) or **Debian** (apt)

I’ll spit out the **monorepo skeleton**, initial **schemas for 60+ actions** (system/net/ssl), a **runner Dockerfile**, and the **UI pages** (Toolbox, SSL Lab, Network Workbench, K8s Explorer) ready to run.
