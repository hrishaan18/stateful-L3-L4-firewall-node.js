#!/usr/bin/env node
"use strict";

const path = require("path");
const { Firewall } = require("./firewall");

const DEFAULT_CONFIG_PATH = path.join(__dirname, "..", "config", "firewall.config.json");

function createFromArgs(args) {
  const configIndex = args.indexOf("--config");
  const configPath = configIndex >= 0 ? args[configIndex + 1] : DEFAULT_CONFIG_PATH;
  return Firewall.fromConfigFile(configPath);
}

function printHelp() {
  console.log(`node-firewall commands:
  self-test
  export-rules --format pf
  export-rules --format iptables
  inspect --src 1.2.3.4 --dst 5.6.7.8 --proto tcp --dport 80 --host example.com --bytes 123
  state
`);
}

function readOption(args, name, fallback = undefined) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : fallback;
}

function runSelfTest() {
  const firewall = createFromArgs(process.argv);
  const samples = [
    { sourceIp: "65.61.137.117", protocol: "tcp", destinationPort: 443 },
    { destinationIp: "44.228.249.3", protocol: "tcp", destinationPort: 443 },
    { sourceIp: "203.0.113.10", protocol: "tcp", destinationPort: 80, host: "plain-http.test" },
    { sourceIp: "203.0.113.10", protocol: "udp", destinationPort: 161 },
    { sourceIp: "203.0.113.10", protocol: "tcp", destinationPort: 22 },
    { sourceIp: "203.0.113.10", protocol: "tcp", destinationPort: 443, host: "ads.badsite.test" },
    { sourceIp: "203.0.113.10", destinationIp: "198.51.100.10", protocol: "tcp", destinationPort: 443, host: "big-traffic.test", bytes: 53687091201 },
  ];

  for (const packet of samples) {
    const verdict = firewall.inspect(packet);
    if (verdict.allowed) {
      throw new Error(`Expected packet to be blocked: ${JSON.stringify(packet)}`);
    }
  }

  console.log("Advanced firewall self-test passed.");
}

function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === "help" || command === "--help") {
    printHelp();
    return;
  }

  const firewall = createFromArgs(process.argv);

  if (command === "self-test") {
    runSelfTest();
    return;
  }

  if (command === "export-rules") {
    const format = readOption(args, "--format", "pf");
    process.stdout.write(format === "iptables" ? firewall.exportIptablesRules() : firewall.exportPfRules());
    return;
  }

  if (command === "inspect") {
    const verdict = firewall.inspect({
      sourceIp: readOption(args, "--src", ""),
      destinationIp: readOption(args, "--dst", ""),
      protocol: readOption(args, "--proto", "tcp"),
      sourcePort: readOption(args, "--sport", 0),
      destinationPort: readOption(args, "--dport", 0),
      host: readOption(args, "--host", ""),
      bytes: Number(readOption(args, "--bytes", 0)),
    });
    console.log(JSON.stringify(verdict, null, 2));
    return;
  }

  if (command === "state") {
    console.log(JSON.stringify(firewall.getStateTable(), null, 2));
    return;
  }

  printHelp();
}

if (require.main === module) {
  main();
}
