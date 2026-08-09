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

## Repository structure

```
01-wazuh-siem-lab/          the project write up and the evidence for it
stacks/siem/                Wazuh manager, indexer and dashboard
  config/wazuh_cluster/       local_rules.xml, where my custom rules live
targets/ssh-victim/         the machine being attacked
attacker/                   the attack tooling
stacks/endpoint/            a second monitored machine
```

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
