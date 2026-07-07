"use strict";

const assert = require("assert");
const { createFirewall } = require("../src/firewall");

const firewall = createFirewall();

for (const ip of ["65.61.137.117", "44.228.249.3", "142.251.39.142"]) {
  assert.strictEqual(
    firewall.inspect({ sourceIp: ip, protocol: "tcp", destinationPort: 443 }).allowed,
    false,
    `${ip} should be blocked as a source IP`
  );

  assert.strictEqual(
    firewall.inspect({ destinationIp: ip, protocol: "udp", destinationPort: 53 }).allowed,
    false,
    `${ip} should be blocked as a destination IP`
  );
}

assert.strictEqual(
  firewall.inspect({ sourceIp: "203.0.113.10", protocol: "tcp", destinationPort: 80, host: "plain-http.test" }).allowed,
  false,
  "TCP destination port 80 should be blocked"
);

assert.strictEqual(
  firewall.inspect({ sourceIp: "203.0.113.10", protocol: "udp", destinationPort: 161 }).allowed,
  false,
  "UDP destination port 161 should be blocked"
);

assert.strictEqual(
  firewall.inspect({ sourceIp: "203.0.113.10", protocol: "tcp", destinationPort: 22 }).allowed,
  false,
  "TCP destination port 22 should be blocked"
);

assert.strictEqual(
  firewall.inspect({ sourceIp: "203.0.113.10", protocol: "tcp", destinationPort: 443, host: "ads.badsite.test" }).allowed,
  false,
  "configured blocked websites should be blocked"
);

const volumeFirewall = createFirewall();
assert.strictEqual(
  volumeFirewall.inspect({
    sourceIp: "203.0.113.10",
    destinationIp: "198.51.100.50",
    protocol: "tcp",
    destinationPort: 443,
    host: "large-download.test",
    bytes: 53687091201,
  }).allowed,
  false,
  "websites sending more than 50 GB should be blocked in the state table"
);

assert.strictEqual(
  volumeFirewall.inspect({
    sourceIp: "203.0.113.10",
    destinationIp: "198.51.100.50",
    protocol: "tcp",
    destinationPort: 443,
    host: "large-download.test",
  }).allowed,
  false,
  "state table should keep blocking a website after it exceeds 50 GB"
);

const dynamicFirewall = createFirewall();
dynamicFirewall.blockIp("198.51.100.25");
assert.strictEqual(
  dynamicFirewall.inspect({ sourceIp: "198.51.100.25", protocol: "tcp", destinationPort: 443 }).allowed,
  false,
  "newly added IP should be blocked"
);

dynamicFirewall.blockPort("udp", 500);
assert.strictEqual(
  dynamicFirewall.inspect({ sourceIp: "203.0.113.10", protocol: "udp", destinationPort: 500 }).allowed,
  false,
  "newly added UDP port should be blocked"
);

assert.strictEqual(
  createFirewall().inspect({ sourceIp: "203.0.113.10", protocol: "udp", destinationPort: 53 }).allowed,
  true,
  "unlisted UDP DNS traffic should be allowed"
);

const pfRules = createFirewall().exportPfRules();
assert.match(pfRules, /65\.61\.137\.117/);
assert.match(pfRules, /proto tcp from any to any port 80/);
assert.match(pfRules, /proto udp from any to any port 161/);

const iptablesRules = createFirewall().exportIptablesRules();
assert.match(iptablesRules, /iptables -A FORWARD -p tcp --dport 22 -j DROP/);

console.log("All advanced firewall tests passed.");
