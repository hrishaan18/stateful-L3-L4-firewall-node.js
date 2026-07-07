# Node L3/L4 Stateful Firewall

This project is a Node.js firewall policy engine with:

- default blocked IPs: `65.61.137.117`, `44.228.249.3`, `142.251.39.142`
- default blocked ports: TCP `80`, UDP `161`, TCP `22`
- blocked website/domain rules
- a state table
- automatic blocking when a flow sends more than `50 GB`
- generated rules for macOS `pf` or Linux `iptables`

## Run checks

```bash
npm test
npm run check
```

## Inspect traffic manually

```bash
node src/cli.js inspect --src 192.168.1.10 --dst 65.61.137.117 --proto tcp --dport 443
node src/cli.js inspect --src 192.168.1.10 --dst 198.51.100.10 --proto tcp --dport 80 --host example.com
```

## Generate whole-network firewall rules

For macOS `pf`:

```bash
npm run rules:pf:file
```

For Linux router/firewall hosts:

```bash
npm run rules:iptables:file
```

To protect a whole network, run generated rules on the router, firewall box, or gateway that forwards the network's traffic. Node.js by itself can inspect traffic it receives, but your operating system firewall or router must enforce rules for every device on the network.

## Edit block lists

Change `/config/firewall.config.json` to add more IPs, ports, websites, or to change the `50 GB` state-table threshold.
