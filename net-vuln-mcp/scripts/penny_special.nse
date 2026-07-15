description = [[
Grab the service banner on each open TCP port and flag known-risky services
(telnet, FTP, SMB/SMBv1, obsolete SSH/HTTP, plaintext or legacy remote-access
services, etc.). Read-only: it only reads the banner a service volunteers - it
never logs in, sends a payload, or exploits anything. Part of openWebBuddy's
net-vuln category, for assessing your own machine / LAN / router.
]]

author = "openWebBuddy"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

local comm = require "comm"
local string = require "string"

-- Only inspect open TCP ports.
portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

-- lowercase substring (matched against "<service> <banner>") -> risk note.
-- Read-only heuristics; extend as needed. Order matters only for readability.
local RISK = {
  {"telnet",       "Telnet: cleartext remote admin - credentials sent in the clear. Disable it."},
  {"ftp",          "FTP: cleartext credentials and data. Prefer SFTP/FTPS; avoid exposing on WAN."},
  {"microsoft-ds", "SMB (445): ensure SMBv1 is disabled (EternalBlue/WannaCry risk) and it is not WAN-exposed."},
  {"netbios",      "NetBIOS (137-139): legacy SMB/name service - a common LAN exposure; disable if unused."},
  {"smbv1",        "SMBv1 detected: obsolete and exploitable - disable SMBv1."},
  {"ssh-1",        "SSHv1: obsolete and cryptographically broken - upgrade to SSHv2."},
  {"ssh-1.99",     "SSH advertises v1 compatibility (1.99) - disable SSHv1 fallback."},
  {"vnc",          "VNC: remote desktop, often weak/no auth - restrict to LAN and require a strong password."},
  {"rdp",          "RDP (3389): a top ransomware entry point - never expose to the internet; use a VPN/NLA."},
  {"ms-wbt-server","RDP (3389): a top ransomware entry point - never expose to the internet; use a VPN/NLA."},
  {"rlogin",       "rlogin: legacy, unauthenticated, cleartext - disable."},
  {"rsh",          "rsh/rexec: legacy cleartext remote shell - disable."},
  {"tftp",         "TFTP: no authentication - a frequent config-leak vector; disable if unused."},
  {"snmp",         "SNMP: often left on the 'public' community string - disable or set a private community."},
  {"http-proxy",   "Open HTTP proxy: can be abused to relay traffic - restrict access."},
  {"mysql",        "MySQL exposed: ensure it is bound to localhost/LAN and not reachable from the WAN."},
  {"ms-sql",       "MS-SQL exposed: ensure it is not reachable from the WAN and uses strong auth."},
  {"mongodb",      "MongoDB exposed: historically shipped with no auth - require auth and bind to LAN."},
  {"redis",        "Redis exposed: default has no auth - bind to localhost and enable a password."},
  {"vsftpd 2.3.4", "vsftpd 2.3.4: this specific build shipped with a known backdoor - upgrade immediately."},
}

-- Match the service name + banner against RISK; return joined notes or nil.
local function match_risk(hay)
  local hits = {}
  local seen = {}
  for _, rule in ipairs(RISK) do
    local needle, note = rule[1], rule[2]
    if string.find(hay, needle, 1, true) and not seen[note] then
      seen[note] = true
      hits[#hits + 1] = note
    end
  end
  if #hits == 0 then
    return nil
  end
  return table.concat(hits, " ")
end

action = function(host, port)
  -- Service name nmap already inferred (port-number based without -sV).
  local svc = (port.service or ""):lower()

  -- Best-effort banner grab: read what the service volunteers, with a short timeout.
  local banner = ""
  local status, resp = comm.get_banner(host, port, {timeout = 3000})
  if status and resp then
    banner = resp
  end

  -- Collapse control chars so the banner stays one compact, printable line.
  local clean = banner:gsub("[%z\1-\31\127]", " "):gsub("%s+", " "):gsub("^%s+", ""):gsub("%s+$", "")
  local hay = (svc .. " " .. clean):lower()

  local risk = match_risk(hay)
  if risk then
    if #clean > 0 then
      return "RISK: " .. risk .. " (banner: " .. clean:sub(1, 80) .. ")"
    end
    return "RISK: " .. risk
  end

  -- Nothing flagged: surface the banner (if any) so a human can eyeball it, else stay quiet.
  if #clean > 0 then
    return "banner: " .. clean:sub(1, 80)
  end
  return nil
end
