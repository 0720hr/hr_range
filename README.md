# hr_range

A security home lab I built to practise detection engineering: setting up a SIEM, writing my own detection rules, attacking the lab, and checking the rules actually catch it.

Everything runs in Docker on one laptop. Every detection here was triggered by a real attack and verified afterwards, not just tested in a simulator and left there.

A SIEM is a Security Information and Event Management system. It collects logs from different machines, applies rules to them, and raises an alert when something looks wrong.

## Projects

### 01. [Wazuh SIEM Detection Lab](01-wazuh-siem-lab/)

Someone guesses an SSH password until they get in, then tries to become root. This project catches every stage of that and blocks the attacker automatically.

It covers setting up Wazuh across three containers, writing custom rules for what happens after the break in, and replacing the default passwords Wazuh ships with.

The part worth reading is a rule I wrote that never fired, even though there was nothing wrong with it. Wazuh raises only one alert per log line, and a rule it already ships with was matching the same lines and winning every time. Finding that meant asking what alert the log line actually produced, rather than what was wrong with my rule.

| | |
|---|---|
| What it detects | Password guessing, account takeover, and privilege escalation to root |
| MITRE techniques | T1110 Brute Force, T1078 Valid Accounts, T1548 Abuse Elevation Control Mechanism |
| Automatic response | Blocks the attacker's address, proven by the attacker's own connection timing out afterwards |
| Hardening | Three service passwords replaced, four unused accounts deleted, all secrets taken out of the repository |

### 02. [SOC Automation](02-soc-automation/)

A SIEM tells you something happened. This project makes something happen back.

When a serious alert is raised, a playbook picks it up automatically. It works out whether the attacker's address is worth investigating, looks it up against a threat intelligence service, emails me either way, and blocks the attacker if the alert says an account was actually taken over.

The part worth reading is a workflow that passed every test I wrote and was completely broken. The test alerts I made up had the shape I assumed the SIEM used. Real ones did not, so the lookup ran against an empty value and every single step reported success while delivering an alert with nothing in it.

| | |
|---|---|
| What it does | Adds threat intelligence to alerts, notifies an analyst, and blocks confirmed compromises |
| Tools | Shuffle, VirusTotal API, Gmail SMTP, the Wazuh API, Python |
| Design decision | The lookup never decides whether you get told, only how urgent it looks |
| How it was checked | Every branch tested twice: that it acts when it should, and refuses when it should not |
| In Python | The playbook's decisions rewritten as a script, with 21 tests run against real alerts from the SIEM |

### 03. [Endpoint Detection with LimaCharlie](03-limacharlie-edr/)

My SIEM reads log files. This project adds a tool that watches the machine itself, then points both at the same computer.

An EDR, short for endpoint detection and response, sits on one machine and records what it actually does: every process that starts, its full command line, which process launched it. I wrote detection rules for it, then put a second agent on the same machine so my existing SIEM watches it too. The result is one attack caught by both tools at once, the endpoint's own view and the log stream's view.

The part worth reading is the network path. The endpoint is a virtual machine and the SIEM runs in containers on the host, and the two would not talk to each other. A Windows firewall block quietly overrode the rule I added to fix it, because in Windows Firewall a block always beats an allow.

| | |
|---|---|
| What it does | Runs an EDR and a SIEM against one Windows endpoint and detects the same attack with both |
| Tools | LimaCharlie, VMware, Sysmon, Wazuh |
| MITRE techniques | T1033 System Owner Discovery, T1059.001 PowerShell, T1027 Obfuscated Files or Information |
| The hard part | Bridging a VMware virtual machine to a Dockerised SIEM across NAT and two firewall layers |

### 04. [Adversary Emulation and Case Management](04-adversary-emulation/)

My other projects built detections. This one tests them, by running known attacker techniques against the lab and measuring what each tool actually caught.

I ran seven MITRE ATT&CK techniques against my Windows endpoint and recorded whether the SIEM and the EDR detected each one. Where a tool missed, I wrote a rule to close the gap and confirmed the fix. I then worked the confirmed detections as a single incident case.

The part worth reading is the finding itself: neither tool was better than the other. The gaps ran in both directions, and which technique each tool caught came down to the rules and telemetry it was configured with, not the tool.

| | |
|---|---|
| What it does | Runs seven attacker techniques against one endpoint and measures SIEM against EDR detection coverage |
| Tools | Atomic Red Team, Wazuh, LimaCharlie, Sysmon, DFIR-IRIS |
| MITRE techniques | T1059.001, T1033, T1087.001, T1082, T1547.001, T1053.005, T1070.004 |
| Output | Three new custom SIEM rules, four custom EDR rules, and one worked incident case |

## Repository structure

```
01-wazuh-siem-lab/          detection project: write up and evidence
02-soc-automation/          automation project: write up and evidence
  enrichment/                 the playbook's decisions in Python, with tests
03-limacharlie-edr/         endpoint detection project: write up and evidence
04-adversary-emulation/     emulation project: coverage matrix, custom rules, case work
stacks/siem/                Wazuh manager, indexer and dashboard
  config/wazuh_cluster/       local_rules.xml, where my custom rules live
targets/ssh-victim/         the machine being attacked
attacker/                   the attack tooling
stacks/endpoint/            a second monitored machine
```

The automation platform, the EDR and the case-management platform all run from their own setup outside this repository. What is here is the Wazuh side, the rules that raise the alerts and the configuration that forwards them, plus the Python version of the automation project's decisions.

## Getting started

### Prerequisites

The indexer needs a higher memory map limit than Linux allows by default, otherwise it fails to start. This needs root:

```
sudo sysctl -w vm.max_map_count=262144
```

Then generate the TLS certificates the three containers use to talk to each other. This runs once and writes them into `stacks/siem/config`:

```
cd stacks/siem && docker compose -f generate-indexer-certs.yml run --rm generator
```

Finally, copy each `.example` file to its real name and put your own passwords in. Nothing will start correctly until you do, because the compose files read them from a `.env` file that is not included here.

### Starting the lab

```
cd stacks/siem        && docker compose up -d    # give the indexer about 90 seconds
cd targets/ssh-victim && docker compose up -d
cd attacker           && docker compose up -d
```

The dashboard is at `https://localhost:443`. The certificate is self signed, so your browser will warn you about it.

## Credentials and secrets

No working credentials are stored in this repository. Real passwords live in a `.env` file that git ignores, and the three configuration files that hold credentials are kept out of version control with example versions committed instead.

The machine being attacked does have weak passwords written into it, `victim:password123` and `root:rootpass123`. That is deliberate, since the whole point is that they get guessed. They were made up for this lab, they are not used anywhere else, and that machine is only reachable from inside the lab's own network with no SSH port open to the outside.
