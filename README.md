# 🎯 Nuclei-Templates-Labs

A comprehensive collection of vulnerable environments paired with ready-to-use Nuclei templates for practical security testing and learning! 🚀

![image (23)](https://github.com/user-attachments/assets/56405711-6c5b-4b58-a98f-972406737452)

## 🎭 Overview

**Nuclei-Templates-Labs** provides security enthusiasts, researchers, and learners with:

- Controlled environments for hands-on security testing.
- Step-by-step exploitation and vulnerability understanding guides.
- Prebuilt Nuclei templates for efficient detection and scanning.
- Real-world attack scenarios to enhance practical security experience.

The labs are containerized for safety, allowing you to experiment without the risks associated with real-world vulnerability exploitation.

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/projectdiscovery/nuclei-templates-labs.git
cd nuclei-templates-labs
```

### 2. Install Dependencies

- Ensure you have **Docker** and **Docker Compose** installed.

```bash
# Install Docker
sudo apt update && sudo apt install docker.io -y

# Install Docker Compose
sudo apt install docker-compose -y

# Optional: Run Docker without sudo
sudo usermod -aG docker $USER
newgrp docker
```

Verify installation:
```bash
docker --version
docker-compose --version
```

### 3. Explore Vulnerable Environments

The repository structure categorizes labs by vulnerability types and protocols:

```bash
# List all categories
ls -la

# Navigate and explore labs
cd http/cves/2024/
ls
```

Each lab contains:
- `docker-compose.yml` for setup
- `README.md` explaining the vulnerability
- Nuclei templates for detection
- Exploitation and remediation guides

### 4. Launch a Vulnerable Environment

Navigate to your chosen lab and launch the environment:

```bash
cd http/cves/2024/CVE-2024-55416
docker-compose up -d
```

Verify your environment:

```bash
docker-compose ps
docker-compose logs
```

Lab interfaces or services typically run on localhost ports documented in each lab's README.

### 5. Install Nuclei

Install Nuclei using Go:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Or use pre-built binaries:

```bash
wget https://github.com/projectdiscovery/nuclei/releases/download/v3.0.0/nuclei_3.0.0_linux_amd64.zip
unzip nuclei_3.0.0_linux_amd64.zip
chmod +x nuclei
sudo mv nuclei /usr/local/bin/
```

Verify Nuclei installation:

```bash
nuclei -version
```

### 6. Run Vulnerability Scans

Execute vulnerability scans using the provided templates:

```bash
nuclei -t cve-2024-55416.yaml -u http://localhost:8080
```

Detailed scans and results saving:

```bash
nuclei -t cve-2024-55416.yaml -u http://localhost:8080 -v
nuclei -t cve-2024-55416.yaml -u http://localhost:8080 -o scan-results.txt
```

## 🔥 Use Cases

- **Security Researchers:** Test and validate vulnerabilities, automate scanning, experiment with exploitation techniques.
- **Learners & Students:** Gain practical security testing experience, understand vulnerabilities, follow structured guides.
- **Organizations & Red Teams:** Train teams, validate detection rules, and develop custom threat detection pipelines.

## 🏗️ Contributing

We encourage community contributions! You can:
- Add new vulnerable labs
- Create or improve Nuclei templates
- Enhance documentation and guides
- Report issues or suggest improvements

Fork the repository, make your changes, and submit a pull request.

## 🎨 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 🐝 Stay Connected

- Follow [ProjectDiscovery](https://github.com/projectdiscovery) for more security tools.
- Join our [Discord community](https://discord.gg/projectdiscovery) to discuss security research and automation.

Happy hacking! ⚙️
