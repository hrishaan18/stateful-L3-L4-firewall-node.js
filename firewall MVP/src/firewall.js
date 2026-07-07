"use strict";

const fs = require("fs");
const net = require("net");
const path = require("path");

const GIGABYTE = 1024 * 1024 * 1024;

const DEFAULT_CONFIG = Object.freeze({
  blockedIps: ["65.61.137.117", "44.228.249.3", "142.251.39.142"],
  blockedPorts: [
    { protocol: "tcp", port: 80 },
    { protocol: "udp", port: 161 },
    { protocol: "tcp", port: 22 },
  ],
  blockedDomains: [
    "example-malware.test",
    "ads.badsite.test",
    "tracking.badsite.test",
    "phishing.badsite.test",
  ],
  trafficLimitBytes: 50 * GIGABYTE,
  httpAutoBlock: {
    enabled: true,
    blockPlainHttp: true,
    blockHosts: true,
  },
  stateTtlSeconds: 24 * 60 * 60,
});

function normalizeProtocol(protocol) {
  return typeof protocol === "string" ? protocol.trim().toLowerCase() : "";
}

function normalizeIp(ip) {
  return typeof ip === "string" ? ip.trim().replace(/^::ffff:/, "") : "";
}

function normalizeDomain(domain) {
  return typeof domain === "string" ? domain.trim().toLowerCase().replace(/\.$/, "") : "";
}

function normalizePort(port) {
  const parsed = Number(port);
  return Number.isInteger(parsed) && parsed >= 1 && parsed <= 65535 ? parsed : null;
}

function assertIp(ip) {
  if (net.isIP(ip) === 0) {
    throw new Error(`Invalid IP address: ${ip}`);
  }
}

function assertProtocol(protocol) {
  if (protocol !== "tcp" && protocol !== "udp") {
    throw new Error(`Invalid protocol: ${protocol}. Expected "tcp" or "udp".`);
  }
}

function portRuleKey(protocol, port) {
  return `${protocol}:${port}`;
}

function flowKey(packet) {
  return [
    normalizeProtocol(packet.protocol),
    normalizeIp(packet.sourceIp),
    normalizePort(packet.sourcePort) || 0,
    normalizeIp(packet.destinationIp),
    normalizePort(packet.destinationPort) || 0,
    normalizeDomain(packet.host || packet.domain || ""),
  ].join("|");
}

function mergeConfig(config) {
  return {
    ...DEFAULT_CONFIG,
    ...config,
    httpAutoBlock: {
      ...DEFAULT_CONFIG.httpAutoBlock,
      ...(config && config.httpAutoBlock ? config.httpAutoBlock : {}),
    },
  };
}

class Firewall {
  constructor(options = {}) {
    const config = mergeConfig(options);

    this.blockedIps = new Set();
    this.blockedPorts = new Set();
    this.blockedDomains = new Set();
    this.stateTable = new Map();
    this.trafficLimitBytes = Number(config.trafficLimitBytes) || DEFAULT_CONFIG.trafficLimitBytes;
    this.httpAutoBlock = config.httpAutoBlock;
    this.stateTtlMs = (Number(config.stateTtlSeconds) || DEFAULT_CONFIG.stateTtlSeconds) * 1000;

    for (const ip of config.blockedIps || []) {
      this.blockIp(ip, "configured IP block");
    }

    for (const rule of config.blockedPorts || []) {
      this.blockPort(rule.protocol, rule.port);
    }

    for (const domain of config.blockedDomains || []) {
      this.blockDomain(domain, "configured website block");
    }
  }

  static fromConfigFile(configPath) {
    const absolutePath = path.resolve(configPath);
    const config = JSON.parse(fs.readFileSync(absolutePath, "utf8"));
    return new Firewall(config);
  }

  blockIp(ip, reason = "manual IP block") {
    const normalized = normalizeIp(ip);
    assertIp(normalized);
    this.blockedIps.add(normalized);
    this.addState({ type: "ip", key: normalized, action: "block", reason });
  }

  unblockIp(ip) {
    const normalized = normalizeIp(ip);
    this.blockedIps.delete(normalized);
    this.stateTable.delete(`ip:${normalized}`);
  }

  blockPort(protocol, port) {
    const normalizedProtocol = normalizeProtocol(protocol);
    const normalizedPort = normalizePort(port);

    assertProtocol(normalizedProtocol);

    if (normalizedPort === null) {
      throw new Error(`Invalid port: ${port}`);
    }

    this.blockedPorts.add(portRuleKey(normalizedProtocol, normalizedPort));
  }

  unblockPort(protocol, port) {
    const normalizedProtocol = normalizeProtocol(protocol);
    const normalizedPort = normalizePort(port);

    if (normalizedPort !== null) {
      this.blockedPorts.delete(portRuleKey(normalizedProtocol, normalizedPort));
    }
  }

  blockDomain(domain, reason = "manual website block") {
    const normalized = normalizeDomain(domain);

    if (!normalized) {
      throw new Error(`Invalid domain: ${domain}`);
    }

    this.blockedDomains.add(normalized);
    this.addState({ type: "domain", key: normalized, action: "block", reason });
  }

  unblockDomain(domain) {
    const normalized = normalizeDomain(domain);
    this.blockedDomains.delete(normalized);
    this.stateTable.delete(`domain:${normalized}`);
  }

  addState(entry) {
    const now = Date.now();
    const id = `${entry.type}:${entry.key}`;
    const previous = this.stateTable.get(id) || {};

    this.stateTable.set(id, {
      id,
      type: entry.type,
      key: entry.key,
      action: entry.action || "block",
      reason: entry.reason || previous.reason || "state table block",
      bytes: entry.bytes === undefined ? previous.bytes || 0 : entry.bytes,
      firstSeen: previous.firstSeen || now,
      lastSeen: now,
      expiresAt: entry.expiresAt || now + this.stateTtlMs,
    });
  }

  pruneState(now = Date.now()) {
    for (const [id, entry] of this.stateTable.entries()) {
      if (entry.expiresAt && entry.expiresAt <= now) {
        this.stateTable.delete(id);
      }
    }
  }

  recordTraffic(packet) {
    const bytes = Math.max(0, Number(packet.bytes) || 0);
    const key = flowKey(packet);
    const now = Date.now();
    const previous = this.stateTable.get(`flow:${key}`) || {
      id: `flow:${key}`,
      type: "flow",
      key,
      action: "track",
      reason: "tracked flow",
      bytes: 0,
      firstSeen: now,
      expiresAt: now + this.stateTtlMs,
    };

    previous.bytes += bytes;
    previous.lastSeen = now;
    previous.expiresAt = now + this.stateTtlMs;
    this.stateTable.set(previous.id, previous);

    if (previous.bytes > this.trafficLimitBytes) {
      const destinationIp = normalizeIp(packet.destinationIp);
      const host = normalizeDomain(packet.host || packet.domain || "");

      if (destinationIp) {
        this.blockIp(destinationIp, `traffic exceeded ${this.trafficLimitBytes} bytes`);
      }

      if (host) {
        this.blockDomain(host, `traffic exceeded ${this.trafficLimitBytes} bytes`);
      }
    }
  }

  inspect(packet = {}) {
    this.pruneState();
    this.recordTraffic(packet);

    const sourceIp = normalizeIp(packet.sourceIp);
    const destinationIp = normalizeIp(packet.destinationIp);
    const protocol = normalizeProtocol(packet.protocol);
    const destinationPort = normalizePort(packet.destinationPort);
    const sourcePort = normalizePort(packet.sourcePort);
    const host = normalizeDomain(packet.host || packet.domain || "");

    const stateVerdict = this.inspectState({ sourceIp, destinationIp, host });
    if (!stateVerdict.allowed) {
      return stateVerdict;
    }

    if (sourceIp && this.blockedIps.has(sourceIp)) {
      return this.blockVerdict(`Blocked source IP ${sourceIp}`);
    }

    if (destinationIp && this.blockedIps.has(destinationIp)) {
      return this.blockVerdict(`Blocked destination IP ${destinationIp}`);
    }

    if (host && this.isDomainBlocked(host)) {
      return this.blockVerdict(`Blocked website ${host}`);
    }

    if (destinationPort !== null && this.blockedPorts.has(portRuleKey(protocol, destinationPort))) {
      this.handleHttpAutoBlock(packet, host, destinationIp, destinationPort);
      return this.blockVerdict(`Blocked ${protocol.toUpperCase()} destination port ${destinationPort}`);
    }

    if (sourcePort !== null && this.blockedPorts.has(portRuleKey(protocol, sourcePort))) {
      return this.blockVerdict(`Blocked ${protocol.toUpperCase()} source port ${sourcePort}`);
    }

    if (this.httpAutoBlock.enabled && this.httpAutoBlock.blockPlainHttp && protocol === "tcp" && destinationPort === 80) {
      this.handleHttpAutoBlock(packet, host, destinationIp, destinationPort);
      return this.blockVerdict("Blocked plain HTTP traffic");
    }

    return {
      allowed: true,
      action: "allow",
      reason: "Allowed by firewall policy",
    };
  }

  inspectState({ sourceIp, destinationIp, host }) {
    for (const key of [sourceIp, destinationIp].filter(Boolean)) {
      const entry = this.stateTable.get(`ip:${key}`);
      if (entry && entry.action === "block") {
        return this.blockVerdict(`Blocked by state table: ${entry.reason}`);
      }
    }

    if (host) {
      const entry = this.findDomainState(host);
      if (entry && entry.action === "block") {
        return this.blockVerdict(`Blocked by state table: ${entry.reason}`);
      }
    }

    return { allowed: true };
  }

  findDomainState(host) {
    for (const domain of this.domainCandidates(host)) {
      const entry = this.stateTable.get(`domain:${domain}`);
      if (entry) {
        return entry;
      }
    }

    return null;
  }

  isDomainBlocked(host) {
    return this.domainCandidates(host).some((domain) => this.blockedDomains.has(domain));
  }

  domainCandidates(host) {
    const normalized = normalizeDomain(host);
    const parts = normalized.split(".");
    const candidates = [];

    for (let index = 0; index < parts.length; index += 1) {
      candidates.push(parts.slice(index).join("."));
    }

    return candidates.filter(Boolean);
  }

  handleHttpAutoBlock(packet, host, destinationIp, destinationPort) {
    if (!this.httpAutoBlock.enabled || destinationPort !== 80) {
      return;
    }

    if (destinationIp) {
      this.blockIp(destinationIp, "plain HTTP destination seen");
    }

    if (this.httpAutoBlock.blockHosts && host) {
      this.blockDomain(host, "plain HTTP website seen");
    }
  }

  blockVerdict(reason) {
    return {
      allowed: false,
      action: "block",
      reason,
    };
  }

  getStateTable() {
    this.pruneState();
    return Array.from(this.stateTable.values()).sort((a, b) => a.id.localeCompare(b.id));
  }

  exportPfRules() {
    const blockedIps = Array.from(this.blockedIps).sort();
    const lines = [
      "# Generated by node-l3-l4-firewall",
      `table <nodefw_blocked_ips> persist { ${blockedIps.join(", ")} }`,
      "block drop quick from <nodefw_blocked_ips> to any",
      "block drop quick from any to <nodefw_blocked_ips>",
    ];

    for (const rule of Array.from(this.blockedPorts).sort()) {
      const [protocol, port] = rule.split(":");
      lines.push(`block drop quick proto ${protocol} from any to any port ${port}`);
    }

    return `${lines.join("\n")}\n`;
  }

  exportIptablesRules() {
    const lines = ["# Generated by node-l3-l4-firewall"];

    for (const ip of Array.from(this.blockedIps).sort()) {
      lines.push(`iptables -A INPUT -s ${ip} -j DROP`);
      lines.push(`iptables -A OUTPUT -d ${ip} -j DROP`);
      lines.push(`iptables -A FORWARD -s ${ip} -j DROP`);
      lines.push(`iptables -A FORWARD -d ${ip} -j DROP`);
    }

    for (const rule of Array.from(this.blockedPorts).sort()) {
      const [protocol, port] = rule.split(":");
      lines.push(`iptables -A INPUT -p ${protocol} --dport ${port} -j DROP`);
      lines.push(`iptables -A FORWARD -p ${protocol} --dport ${port} -j DROP`);
    }

    return `${lines.join("\n")}\n`;
  }

  middleware() {
    return (req, res, next) => {
      const verdict = this.inspect({
        sourceIp: getRequestIp(req),
        protocol: "tcp",
        destinationPort: req.socket && req.socket.localPort,
        host: req.headers && req.headers.host,
        bytes: Number(req.headers && req.headers["content-length"]) || 0,
      });

      if (!verdict.allowed) {
        res.statusCode = 403;
        res.end("Forbidden");
        return;
      }

      next();
    };
  }
}

function getRequestIp(req) {
  const forwardedFor = req.headers && req.headers["x-forwarded-for"];

  if (typeof forwardedFor === "string" && forwardedFor.trim()) {
    return normalizeIp(forwardedFor.split(",")[0]);
  }

  return normalizeIp(
    (req.socket && req.socket.remoteAddress) ||
    (req.connection && req.connection.remoteAddress) ||
    ""
  );
}

function createFirewall(options) {
  return new Firewall(options);
}

module.exports = {
  Firewall,
  createFirewall,
  DEFAULT_CONFIG,
};
