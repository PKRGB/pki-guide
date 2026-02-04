# Complete Guide: Setting Up CA and HTTPS for Your Network Devices

**Version 1.2 - February 2026**

## Overview

This guide walks you through creating a Certificate Authority (CA) on your Mac/Linux workstation, generating certificates for two network devices, and configuring HTTPS with trusted certificates.

### What you'll set up:
- Certificate Authority on your workstation
- HTTPS for Device1 (${DEVICE1_IP}) - ${DEVICE1_HOSTNAME}.lan
- HTTPS for Device2 (${DEVICE2_IP}) - ${DEVICE2_HOSTNAME}.lan
- Trusted certificates in browsers and on the devices themselves

**Important:** We use .lan domain extension instead of .local to avoid mDNS conflicts on iOS/macOS devices.

---

## Quick Reference: Your Values

Fill this out before starting:

| Variable | Your Value | Example |
|----------|------------|---------|
| ${DEVICE1_HOSTNAME} | _________ | pihole |
| ${DEVICE1_IP} | _________ | 192.168.1.100 |
| ${DEVICE2_HOSTNAME} | _________ | suricata |
| ${DEVICE2_IP} | _________ | 192.168.1.101 |
| ${COUNTRY} | _________ | US |
| ${STATE} | _________ | TX |
| ${CITY} | _________ | Houston |
| ${ORG_NAME} | _________ | HomeLab |
| ${ORG_UNIT} | _________ | IT |
| ${EMAIL} | _________ | admin@example.com |
| CA Passphrase | _________ | (SAVE SECURELY!) |

Keep this reference handy while following the guide.

---

## Part 1: Create Certificate Authority on Mac/Linux

### Step 1: Install OpenSSL (if needed)

**macOS:**
```bash
# Check if OpenSSL is installed
openssl version

# If not installed, install via Homebrew
brew install openssl
```

**Linux:**
```bash
# Check if OpenSSL is installed
openssl version

# If not installed
sudo apt install openssl  # Debian/Ubuntu
sudo yum install openssl  # RHEL/CentOS
```

### Step 2: Create CA Directory Structure

```bash
# Create directory for CA files
mkdir -p ~/CA/{certs,crl,newcerts,private,requests}
cd ~/CA

# Create index and serial files
touch index.txt
echo 1000 > serial
echo 1000 > crlnumber
```

### Step 3: Create CA Configuration File

```bash
cat > ~/CA/openssl.cnf << 'EOF'
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = REPLACE_WITH_HOME/CA
certs             = $dir/certs
crl_dir           = $dir/crl
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
RANDFILE          = $dir/private/.rand
private_key       = $dir/private/ca.key
certificate       = $dir/certs/ca.crt
crlnumber         = $dir/crlnumber
crl               = $dir/crl/ca.crl
crl_extensions    = crl_ext
default_crl_days  = 30
default_md        = sha256
name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_loose

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 4096
distinguished_name  = req_distinguished_name
string_mask         = utf8only
default_md          = sha256
x509_extensions     = v3_ca

[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ crl_ext ]
authorityKeyIdentifier=keyid:always

[ ocsp ]
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning

[ alt_names ]
DNS.1 = ${DEVICE1_HOSTNAME}.lan
DNS.2 = ${DEVICE1_HOSTNAME}
IP.1  = ${DEVICE1_IP}
EOF
```

**Replace REPLACE_WITH_HOME with your actual home directory:**

```bash
# On macOS, run:
sed -i '' "s|REPLACE_WITH_HOME|$HOME|g" ~/CA/openssl.cnf

# On Linux, run:
sed -i "s|REPLACE_WITH_HOME|$HOME|g" ~/CA/openssl.cnf
```

**Important Note:** The [ alt_names ] section will be updated before signing each certificate. This is a placeholder for Device1 initially.

### Step 4: Generate CA Private Key

```bash
cd ~/CA

# Generate 4096-bit RSA key (you'll be prompted for a passphrase)
openssl genrsa -aes256 -out private/ca.key 4096

# Set strict permissions
chmod 400 private/ca.key
```

**CRITICAL:** Save this passphrase securely in a password manager immediately. You'll need it to sign certificates and cannot recover it if lost.

### Step 5: Create CA Certificate

```bash
# Create self-signed root certificate (valid for 10 years)
openssl req -config openssl.cnf \
    -key private/ca.key \
    -new -x509 -days 3650 -sha256 -extensions v3_ca \
    -out certs/ca.crt

# When prompted, enter your information:
# Country Name: ${COUNTRY}
# State: ${STATE}
# Locality: ${CITY}
# Organization Name: ${ORG_NAME}
# Organizational Unit: ${ORG_UNIT}
# Common Name: Root CA
# Email: ${EMAIL}
```

### Step 6: Verify CA Certificate

```bash
# Verify the certificate
openssl x509 -noout -text -in certs/ca.crt

# Should show:
# - Issuer and Subject are the same (self-signed)
# - CA:TRUE
# - Valid for 10 years
```

---

## Part 2: Trust the CA on Your Workstation

### Step 7: Add CA to System Trust Store

**macOS:**
```bash
# Open the CA certificate
open ~/CA/certs/ca.crt
```

In Keychain Access:
1. The certificate will be added to "login" keychain
2. Double-click the certificate named "Root CA"
3. Expand the "Trust" section
4. Set "When using this certificate" to "Always Trust"
5. Close the window - you'll be prompted for your password
6. Enter your password to confirm

**Linux:**
```bash
# Copy CA to system trust store
sudo cp ~/CA/certs/ca.crt /usr/local/share/ca-certificates/home-ca.crt
sudo update-ca-certificates

# Should show: 1 added
```

### Step 8: Verify Trust

**macOS:**
```bash
security verify-cert -c ~/CA/certs/ca.crt
# Should return: ...certificate verification successful.
```

**Linux:**
```bash
openssl verify -CAfile ~/CA/certs/ca.crt ~/CA/certs/ca.crt
# Should return: ...OK
```

---

## Part 3: Generate Certificate for Device1

### Step 9: Create Certificate Signing Request (CSR) Configuration

```bash
# Note: You'll need to edit this file after creation to replace ${VARIABLE} placeholders
cat > ~/CA/requests/${DEVICE1_HOSTNAME}.cnf << 'EOF'
[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = req_ext
prompt             = no

[ req_distinguished_name ]
countryName                = ${COUNTRY}
stateOrProvinceName        = ${STATE}
localityName              = ${CITY}
organizationName          = ${ORG_NAME}
organizationalUnitName    = ${ORG_UNIT}
commonName                = ${DEVICE1_HOSTNAME}.lan
emailAddress              = ${EMAIL}

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${DEVICE1_HOSTNAME}.lan
DNS.2 = ${DEVICE1_HOSTNAME}
IP.1  = ${DEVICE1_IP}
EOF

# Now edit the file to replace variables with your actual values
nano ~/CA/requests/${DEVICE1_HOSTNAME}.cnf
# Replace all ${COUNTRY}, ${STATE}, ${CITY}, ${ORG_NAME}, ${ORG_UNIT}, 
# ${DEVICE1_HOSTNAME}, ${DEVICE1_IP}, and ${EMAIL} with your actual values
# Save and exit (Ctrl+O, Enter, Ctrl+X)
```

### Step 10: Generate Private Key for Device1

```bash
cd ~/CA

# Generate 2048-bit key (no passphrase for server use)
openssl genrsa -out requests/${DEVICE1_HOSTNAME}.key 2048

# Set permissions
chmod 400 requests/${DEVICE1_HOSTNAME}.key
```

### Step 11: Create CSR for Device1

```bash
# Generate CSR with extensions
openssl req -new -key requests/${DEVICE1_HOSTNAME}.key \
    -out requests/${DEVICE1_HOSTNAME}.csr \
    -config requests/${DEVICE1_HOSTNAME}.cnf \
    -reqexts req_ext

# Verify CSR includes SANs
openssl req -text -noout -in requests/${DEVICE1_HOSTNAME}.csr | grep -A5 "Subject Alternative Name"

# Should show: DNS:${DEVICE1_HOSTNAME}.lan, DNS:${DEVICE1_HOSTNAME}, IP Address:${DEVICE1_IP}
```

### Step 12: Update openssl.cnf for Device1 and Sign Certificate

```bash
cd ~/CA

# CRITICAL: Update the [ alt_names ] section in openssl.cnf
nano openssl.cnf
```

Find the [ alt_names ] section at the bottom and update it:
```
[ alt_names ]
DNS.1 = ${DEVICE1_HOSTNAME}.lan
DNS.2 = ${DEVICE1_HOSTNAME}
IP.1  = ${DEVICE1_IP}
```

Save and exit, then sign:

```bash
# Sign the certificate with your CA (valid for 1 year)
openssl ca -config openssl.cnf \
    -extensions server_cert -days 375 -notext -md sha256 \
    -in requests/${DEVICE1_HOSTNAME}.csr \
    -out certs/${DEVICE1_HOSTNAME}.crt

# Type 'y' to confirm (twice)
# Enter CA passphrase when prompted

# Verify the signed certificate has SANs
openssl x509 -in certs/${DEVICE1_HOSTNAME}.crt -text -noout | grep -A5 "Subject Alternative Name"

# Should show: DNS:${DEVICE1_HOSTNAME}.lan, DNS:${DEVICE1_HOSTNAME}, IP Address:${DEVICE1_IP}
```

---

## Part 4: Generate Certificate for Device2

### Step 13: Create CSR Configuration for Device2

```bash
# Note: You'll need to edit this file after creation to replace ${VARIABLE} placeholders
cat > ~/CA/requests/${DEVICE2_HOSTNAME}.cnf << 'EOF'
[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = req_ext
prompt             = no

[ req_distinguished_name ]
countryName                = ${COUNTRY}
stateOrProvinceName        = ${STATE}
localityName              = ${CITY}
organizationName          = ${ORG_NAME}
organizationalUnitName    = ${ORG_UNIT}
commonName                = ${DEVICE2_HOSTNAME}.lan
emailAddress              = ${EMAIL}

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${DEVICE2_HOSTNAME}.lan
DNS.2 = ${DEVICE2_HOSTNAME}
IP.1  = ${DEVICE2_IP}
EOF

# Now edit the file to replace variables with your actual values
nano ~/CA/requests/${DEVICE2_HOSTNAME}.cnf
# Replace all ${COUNTRY}, ${STATE}, ${CITY}, ${ORG_NAME}, ${ORG_UNIT},
# ${DEVICE2_HOSTNAME}, ${DEVICE2_IP}, and ${EMAIL} with your actual values
# Save and exit (Ctrl+O, Enter, Ctrl+X)
```

### Step 14: Generate Private Key for Device2

```bash
cd ~/CA

# Generate 2048-bit key
openssl genrsa -out requests/${DEVICE2_HOSTNAME}.key 2048

# Set permissions
chmod 400 requests/${DEVICE2_HOSTNAME}.key
```

### Step 15: Create CSR for Device2

```bash
# Generate CSR with extensions
openssl req -new -key requests/${DEVICE2_HOSTNAME}.key \
    -out requests/${DEVICE2_HOSTNAME}.csr \
    -config requests/${DEVICE2_HOSTNAME}.cnf \
    -reqexts req_ext

# Verify CSR includes SANs
openssl req -text -noout -in requests/${DEVICE2_HOSTNAME}.csr | grep -A5 "Subject Alternative Name"

# Should show: DNS:${DEVICE2_HOSTNAME}.lan, DNS:${DEVICE2_HOSTNAME}, IP Address:${DEVICE2_IP}
```

### Step 16: Update openssl.cnf for Device2 and Sign Certificate

```bash
cd ~/CA

# CRITICAL: Update the [ alt_names ] section in openssl.cnf
nano openssl.cnf
```

Find the [ alt_names ] section and change it to:
```
[ alt_names ]
DNS.1 = ${DEVICE2_HOSTNAME}.lan
DNS.2 = ${DEVICE2_HOSTNAME}
IP.1  = ${DEVICE2_IP}
```

Save and exit, then sign:

```bash
# Sign the certificate with your CA
openssl ca -config openssl.cnf \
    -extensions server_cert -days 375 -notext -md sha256 \
    -in requests/${DEVICE2_HOSTNAME}.csr \
    -out certs/${DEVICE2_HOSTNAME}.crt

# Type 'y' to confirm (twice)
# Enter CA passphrase when prompted

# Verify the signed certificate has SANs
openssl x509 -in certs/${DEVICE2_HOSTNAME}.crt -text -noout | grep -A5 "Subject Alternative Name"

# Should show: DNS:${DEVICE2_HOSTNAME}.lan, DNS:${DEVICE2_HOSTNAME}, IP Address:${DEVICE2_IP}
```

---

## Part 5: Install Certificates on Your Devices

The installation steps depend on what web server your device uses. Common scenarios:

---

### Scenario A: Pi-hole (using Pi-hole FTL v6+)

#### Important: Pi-hole FTL Certificate Requirements

**Pi-hole FTL has specific certificate chain requirements that differ from traditional web servers like Nginx or Apache.**

Unlike Nginx (which uses separate `ssl_certificate` and `ssl_certificate_key` directives), Pi-hole's FTL web server requires all certificate components in a **single PEM file** in this exact order:

1. Server certificate (pihole.crt)
2. CA certificate (ca.crt)
3. Private key (pihole.key)

**Why this matters:**
- If the CA certificate is missing from the chain, browsers will show "Unable to verify the first certificate"
- If the order is incorrect, FTL won't serve HTTPS properly
- Other web servers handle chain assembly automatically; FTL requires manual bundling

**Common mistake:** Many guides only include the server certificate and key in `tls.pem`, omitting the CA certificate. This causes certificate validation errors even though the certificates are technically valid.

This guide includes the CA certificate in the PEM bundle (Step 18a) to ensure the full certificate chain is presented to clients, eliminating trust errors.

---

#### Step 17a: Copy Certificates to Pi-hole

From your workstation, copy the certificates AND the CA certificate:

```bash
# Copy server certificate and key (replace ${USER} and ${DEVICE1_IP})
scp ~/CA/certs/${DEVICE1_HOSTNAME}.crt ${USER}@${DEVICE1_IP}:/tmp/
scp ~/CA/requests/${DEVICE1_HOSTNAME}.key ${USER}@${DEVICE1_IP}:/tmp/

# Copy CA certificate (CRITICAL - needed for certificate chain)
scp ~/CA/certs/ca.crt ${USER}@${DEVICE1_IP}:/tmp/
```

#### Step 18a: SSH into Pi-hole and Install Certificates

```bash
# SSH into Pi-hole
ssh ${USER}@${DEVICE1_IP}

# Move certificates to proper location
sudo cp /tmp/${DEVICE1_HOSTNAME}.crt /etc/pihole/
sudo cp /tmp/${DEVICE1_HOSTNAME}.key /etc/pihole/
sudo cp /tmp/ca.crt /etc/pihole/tls_ca.crt

# Create combined PEM file with FULL CHAIN (Pi-hole FTL requires this format)
# Order matters: certificate, CA cert, then private key
sudo bash -c "cat /etc/pihole/${DEVICE1_HOSTNAME}.crt /etc/pihole/tls_ca.crt /etc/pihole/${DEVICE1_HOSTNAME}.key > /etc/pihole/tls.pem"

# Set ownership and permissions
sudo chown pihole:pihole /etc/pihole/tls.pem
sudo chmod 600 /etc/pihole/tls.pem

# Verify the PEM has correct SANs
sudo openssl x509 -in /etc/pihole/tls.pem -text -noout | grep -A3 "Subject Alternative Name"
# Should show: DNS:${DEVICE1_HOSTNAME}.lan, DNS:${DEVICE1_HOSTNAME}, IP Address:${DEVICE1_IP}

# Verify the PEM contains full chain (should show 2 certificates + 1 key)
sudo grep -c "BEGIN CERTIFICATE" /etc/pihole/tls.pem
# Should return: 2

sudo grep -c "BEGIN.*PRIVATE KEY" /etc/pihole/tls.pem
# Should return: 1
```

#### Step 19a: Configure Pi-hole FTL for HTTPS

```bash
# Set the domain name
sudo pihole-FTL --config webserver.domain '${DEVICE1_HOSTNAME}.lan'

# Restart FTL to enable HTTPS
sudo service pihole-FTL restart

# Verify FTL is listening on port 443
sudo lsof -i :443
# Should show pihole-FTL listening on port 443

# Verify the server is sending the full certificate chain
openssl s_client -connect ${DEVICE1_HOSTNAME}.lan:443 -servername ${DEVICE1_HOSTNAME}.lan -showcerts </dev/null 2>/dev/null | grep -c "BEGIN CERTIFICATE"
# Should return: 2

# If using UFW firewall, allow HTTPS
sudo ufw allow 443/tcp
sudo ufw reload
```

#### Step 20a: Configure Local DNS Records (if Pi-hole is your DNS server)

```bash
# Enable dnsmasq.d directory
sudo pihole-FTL --config misc.etc_dnsmasq_d true

# Create custom DNS file
sudo nano /etc/dnsmasq.d/02-custom-dns.conf
```

Add these lines:
```
address=/${DEVICE1_HOSTNAME}.lan/${DEVICE1_IP}
address=/${DEVICE2_HOSTNAME}.lan/${DEVICE2_IP}
```

Save and exit (Ctrl+O, Enter, Ctrl+X), then:

```bash
# Restart FTL to load DNS records
sudo service pihole-FTL restart

# Test DNS resolution
dig ${DEVICE1_HOSTNAME}.lan @127.0.0.1
dig ${DEVICE2_HOSTNAME}.lan @127.0.0.1
# Both should return the correct IP addresses
```

#### Step 21a: Install CA Certificate to System Trust Store

This ensures the Pi itself trusts the certificate (for local access and system tools):

```bash
# Copy CA certificate to system trust store
sudo cp /etc/pihole/tls_ca.crt /usr/local/share/ca-certificates/homelab-root-ca.crt

# Update system certificates
sudo update-ca-certificates
# Should see: "1 added, 0 removed"

# Verify system trusts the certificate
openssl s_client -connect ${DEVICE1_HOSTNAME}.lan:443 -servername ${DEVICE1_HOSTNAME}.lan </dev/null 2>&1 | grep "Verify return code"
# Should return: Verify return code: 0 (ok)
```

#### Step 22a: Install CA Certificate to Chromium (for local Pi GUI access)

If you need to access the Pi-hole admin interface from the Pi's own browser:

```bash
# Install NSS tools if not present
sudo apt install libnss3-tools

# Add CA certificate to Chromium's certificate database
cp /tmp/ca.crt ~/ca.crt
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "Homelab Root CA" -i ~/ca.crt
rm ~/ca.crt

# Verify it was added
certutil -d sql:$HOME/.pki/nssdb -L
# Should show: Homelab Root CA                                              C,,

# Launch Chromium with disabled keyring (avoids password prompts)
DISPLAY=:0 chromium-browser --password-store=basic https://${DEVICE1_HOSTNAME}.lan/admin &

# Clean up temporary files
rm /tmp/ca.crt /tmp/${DEVICE1_HOSTNAME}.crt /tmp/${DEVICE1_HOSTNAME}.key
```

#### Step 23a: Verification Checklist

From any device on your network with the CA certificate installed:
- [ ] Navigate to `https://${DEVICE1_HOSTNAME}.lan/admin`
- [ ] Browser shows secure connection (green padlock)
- [ ] Certificate shows: Issued to: ${DEVICE1_HOSTNAME}.lan, Issued by: Your Root CA
- [ ] No certificate warnings or errors

From the Pi itself:

```bash
# Verify certificate chain
openssl s_client -connect ${DEVICE1_HOSTNAME}.lan:443 -servername ${DEVICE1_HOSTNAME}.lan </dev/null 2>&1 | grep "Verify return code"
# Should return: Verify return code: 0 (ok)

# Verify FTL is serving HTTPS
curl -I https://${DEVICE1_HOSTNAME}.lan/admin
# Should return: HTTP/2 200
```

Exit device:
```bash
exit
```

#### Troubleshooting Notes - Pi-hole

**If browser shows "Not Secure" on the Pi itself:**
- Ensure CA cert is in system trust store (Step 21a)
- Ensure CA cert is in Chromium's NSS database (Step 22a)
- Restart Chromium completely: `pkill chromium`

**If other devices show "Not Secure":**
- Install the CA certificate (`ca.crt`) on each device
- iOS: Settings → General → VPN & Device Management → Install Profile
- macOS: Keychain Access → Import → Always Trust
- Windows: Install to Trusted Root Certification Authorities

**If certificate chain fails:**
- Verify `tls.pem` contains 2 certificates and 1 key
- Ensure order is: server cert, CA cert, then private key
- Rebuild using Step 18a if needed

---

### Scenario B: Nginx Web Server

**Note for Nginx:** Unlike Pi-hole FTL, Nginx uses separate certificate files and automatically handles the certificate chain. You only need to provide the server certificate and key - the CA certificate is optional (can be provided via `ssl_trusted_certificate` for OCSP stapling, but not required for basic HTTPS).

#### Step 17b: Copy Certificates

```bash
# From your workstation
scp ~/CA/certs/${DEVICE2_HOSTNAME}.crt ${USER}@${DEVICE2_IP}:/tmp/
scp ~/CA/requests/${DEVICE2_HOSTNAME}.key ${USER}@${DEVICE2_IP}:/tmp/
```

#### Step 18b: SSH and Install Certificates

```bash
ssh ${USER}@${DEVICE2_IP}

# Create SSL directory
sudo mkdir -p /etc/nginx/ssl

# Move certificates
sudo cp /tmp/${DEVICE2_HOSTNAME}.crt /etc/nginx/ssl/
sudo cp /tmp/${DEVICE2_HOSTNAME}.key /etc/nginx/ssl/

# Set permissions
sudo chmod 644 /etc/nginx/ssl/${DEVICE2_HOSTNAME}.crt
sudo chmod 600 /etc/nginx/ssl/${DEVICE2_HOSTNAME}.key
sudo chown root:root /etc/nginx/ssl/*
```

#### Step 19b: Configure Nginx for HTTPS

```bash
# Backup existing config
sudo cp /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/default.backup

# Edit nginx config
sudo nano /etc/nginx/sites-enabled/default
```

Update to include:

```nginx
# Redirect HTTP to HTTPS
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name ${DEVICE2_HOSTNAME}.lan ${DEVICE2_IP};
    return 301 https://$server_name$request_uri;
}

# HTTPS Server
server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name ${DEVICE2_HOSTNAME}.lan ${DEVICE2_IP};

    # SSL Configuration
    ssl_certificate /etc/nginx/ssl/${DEVICE2_HOSTNAME}.crt;
    ssl_certificate_key /etc/nginx/ssl/${DEVICE2_HOSTNAME}.key;
    
    # SSL Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Your existing location blocks go here
    root /var/www/html;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }
}
```

#### Step 20b: Test and Restart Nginx

```bash
# Test configuration
sudo nginx -t

# If OK, restart
sudo systemctl restart nginx

# Verify listening on 443
sudo lsof -i :443

# If using UFW firewall, allow HTTPS
sudo ufw allow 443/tcp
sudo ufw reload

exit
```

---

### Scenario C: Apache Web Server

**Note for Apache:** Like Nginx, Apache uses separate certificate files and automatically handles the certificate chain. The CA certificate is optional (can be provided via `SSLCertificateChainFile` for intermediate certificates, but not required for basic HTTPS with a root CA).

#### Step 17c: Copy Certificates

```bash
scp ~/CA/certs/${DEVICE2_HOSTNAME}.crt ${USER}@${DEVICE2_IP}:/tmp/
scp ~/CA/requests/${DEVICE2_HOSTNAME}.key ${USER}@${DEVICE2_IP}:/tmp/
```

#### Step 18c: SSH and Install

```bash
ssh ${USER}@${DEVICE2_IP}

# Create SSL directory
sudo mkdir -p /etc/apache2/ssl

# Move certificates
sudo cp /tmp/${DEVICE2_HOSTNAME}.crt /etc/apache2/ssl/
sudo cp /tmp/${DEVICE2_HOSTNAME}.key /etc/apache2/ssl/

# Set permissions
sudo chmod 644 /etc/apache2/ssl/${DEVICE2_HOSTNAME}.crt
sudo chmod 600 /etc/apache2/ssl/${DEVICE2_HOSTNAME}.key
```

#### Step 19c: Enable SSL Module and Configure

```bash
# Enable SSL module
sudo a2enmod ssl

# Edit SSL site config
sudo nano /etc/apache2/sites-available/default-ssl.conf
```

Update:

```apache
<VirtualHost *:443>
    ServerName ${DEVICE2_HOSTNAME}.lan
    ServerAlias ${DEVICE2_HOSTNAME}

    SSLEngine on
    SSLCertificateFile /etc/apache2/ssl/${DEVICE2_HOSTNAME}.crt
    SSLCertificateKeyFile /etc/apache2/ssl/${DEVICE2_HOSTNAME}.key

    # Your existing config...
</VirtualHost>
```

#### Step 20c: Enable Site and Restart

```bash
# Enable SSL site
sudo a2ensite default-ssl

# Test config
sudo apache2ctl configtest

# Restart
sudo systemctl restart apache2

# If using UFW firewall, allow HTTPS
sudo ufw allow 443/tcp
sudo ufw reload

exit
```

---

## Part 5.5: Verify Certificate Installation (Before DNS Configuration)

Before configuring DNS, verify certificates are properly installed:

**Test with IP address:**

```bash
# This should fail with certificate error (expected - proves cert is active)
curl -k https://${DEVICE1_IP}/

# Check what certificate is being served
openssl s_client -connect ${DEVICE1_IP}:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer
# Should show: subject=CN=${DEVICE1_HOSTNAME}.lan, issuer=CN=Root CA
```

**Why this matters:** Confirms HTTPS is active before troubleshooting DNS issues separately.

---

## Part 6: Configure DNS Resolution

### Add Hostname Resolution

On your workstation's hosts file:

**macOS/Linux:**
```bash
sudo nano /etc/hosts
```

Add:
```
${DEVICE1_IP} ${DEVICE1_HOSTNAME}.lan
${DEVICE2_IP} ${DEVICE2_HOSTNAME}.lan
```

**Windows:** Edit `C:\Windows\System32\drivers\etc\hosts` (as Administrator) and add the same lines.

---

## Part 7: Test HTTPS Access

### Test from Your Workstation

**In your browser:**
- `https://${DEVICE1_HOSTNAME}.lan/`
- `https://${DEVICE2_HOSTNAME}.lan/`

Should show:
- ✅ Green padlock (trusted certificate)
- ✅ No certificate warnings
- ✅ Content loads properly

**Important:** Test from a different device than where you installed the certificates to verify the trust chain works.

**Test with curl:**
```bash
curl -v https://${DEVICE1_HOSTNAME}.lan/
curl -v https://${DEVICE2_HOSTNAME}.lan/
```

### Verify Certificate Chain

```bash
openssl s_client -connect ${DEVICE1_IP}:443 -showcerts
# Should show: Verify return code: 0 (ok)
```

---

## Part 8: Install CA on Mobile Devices (Optional)

### iPhone/iPad

1. Email or upload `~/CA/certs/ca.crt` to your device
2. Download and tap to install
3. Settings → General → VPN & Device Management → Install profile
4. **CRITICAL:** Settings → General → About → Certificate Trust Settings
5. Enable trust for "Root CA"

### Android

1. Download `ca.crt`
2. Settings → Security → Install certificate → CA certificate
3. Select the file

---

## Part 9: Install CA on Devices with Local Browsers

If your device runs a local browser (e.g., Chromium for dashboards):

```bash
# Copy CA to device
scp ~/CA/certs/ca.crt ${USER}@${DEVICE_IP}:/tmp/

# SSH in
ssh ${USER}@${DEVICE_IP}

# Install in system store
sudo cp /tmp/ca.crt /usr/local/share/ca-certificates/home-ca.crt
sudo update-ca-certificates

# Install for Chromium/Chrome
sudo apt install libnss3-tools
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "Home Root CA" -i /usr/local/share/ca-certificates/home-ca.crt

# Reboot
sudo reboot
```

---

## Certificate Maintenance

### Renewal (Before 375-Day Expiration)

Update the [ alt_names ] section in `openssl.cnf`, then:

```bash
cd ~/CA

# Generate new CSR (reuse existing key)
openssl req -new -key requests/${DEVICE_HOSTNAME}.key \
    -out requests/${DEVICE_HOSTNAME}.csr \
    -config requests/${DEVICE_HOSTNAME}.cnf \
    -reqexts req_ext

# Sign the new certificate
openssl ca -config openssl.cnf \
    -extensions server_cert -days 375 -notext -md sha256 \
    -in requests/${DEVICE_HOSTNAME}.csr \
    -out certs/${DEVICE_HOSTNAME}-renewed.crt

# Move the renewed cert to replace the old one
mv certs/${DEVICE_HOSTNAME}-renewed.crt certs/${DEVICE_HOSTNAME}.crt
```

**Deploy to device (example for Pi-hole):**

```bash
# Copy new certificate to device
scp ~/CA/certs/${DEVICE_HOSTNAME}.crt ${USER}@${DEVICE_IP}:/tmp/

# SSH into device
ssh ${USER}@${DEVICE_IP}

# Update certificate
sudo cp /tmp/${DEVICE_HOSTNAME}.crt /etc/pihole/

# Rebuild PEM file with new certificate
sudo bash -c "cat /etc/pihole/${DEVICE_HOSTNAME}.crt /etc/pihole/tls_ca.crt /etc/pihole/${DEVICE_HOSTNAME}.key > /etc/pihole/tls.pem"

# Set permissions
sudo chown pihole:pihole /etc/pihole/tls.pem
sudo chmod 600 /etc/pihole/tls.pem

# Restart service
sudo service pihole-FTL restart

# Exit
exit
```

**For Nginx/Apache:** Follow similar process, copying the new `.crt` file to the appropriate location and restarting the web server.

---

## Common Mistakes to Avoid

1. **Forgetting CA passphrase**: Write it down during Step 4 - you can't recover it
2. **Wrong certificate order in tls.pem**: For Pi-hole, must be: cert, CA, key (not key, cert, CA)
3. **Not updating [ alt_names ] before signing**: Each device needs its own SANs
4. **Using .local instead of .lan**: Will break on iOS/macOS devices
5. **Forgetting to copy ca.crt to Pi-hole**: Most common cause of "Unable to verify" errors
6. **Not installing CA on client devices**: Certificates won't be trusted until CA is installed

---

## Troubleshooting

### Certificate Not Trusted

- Verify CA is installed in system trust store
- Check trust settings (macOS: "Always Trust")
- Clear browser cache
- Restart browser completely

### Connection Refused

- Verify service is listening: `sudo lsof -i :443`
- Check firewall rules: `sudo ufw status`
- Verify certificates are in correct location
- Check service logs for errors

### DNS Not Resolving

- Check hosts file entries
- Verify DNS server configuration
- Flush DNS cache (restart device)
- Test with `dig` or `nslookup`

### Certificate Expired

Certificates are valid for 375 days. If expired:

1. Check expiration date:
   ```bash
   openssl x509 -in ~/CA/certs/${DEVICE_HOSTNAME}.crt -noout -dates
   ```

2. Generate and deploy new certificate (see "Renewal" section)

3. Set calendar reminder: 1 year from today to renew all certificates

---

## Security Best Practices

### Backup Strategy

**Full backup:**
```bash
tar -czf CA-backup-$(date +%Y%m%d).tar.gz ~/CA/
```

**Storage:**
- Store encrypted offsite (encrypted USB drive, encrypted cloud storage)
- **CRITICAL:** Backup includes the CA private key passphrase (store separately in password manager)
- Test restore procedure annually
- If CA is compromised, ALL certificates must be regenerated

### Other Best Practices

- **Protect CA private key passphrase** - use password manager
- **Set certificate renewal reminders** - before 375-day expiration
- **Never share CA private key**
- **Use strong passphrases** (minimum 20 characters)
- **Limit CA access** - only use for signing, keep offline when possible
- **Monitor certificate expiration** - automate checks if possible

---

## Important Notes

### Why .lan?

The `.local` domain is reserved for mDNS. iOS/macOS prioritize mDNS for `.local`, causing DNS resolution failures. Use `.lan` to avoid conflicts.

### File Locations

- **CA certificate:** `~/CA/certs/ca.crt`
- **CA private key:** `~/CA/private/ca.key`
- **Device certificates:** `~/CA/certs/${DEVICE_HOSTNAME}.crt`
- **Device keys:** `~/CA/requests/${DEVICE_HOSTNAME}.key`

---

**Your network now has proper HTTPS with trusted certificates!** 🔒

---

**Version History:**
- v1.2 (February 2026): Added certificate chain clarifications, improved troubleshooting, enhanced security notes
- v1.1: Initial public release
