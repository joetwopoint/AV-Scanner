local severityRank = { low = 1, medium = 2, high = 3, critical = 4 }

local function nowStamp()
  local t = os.date('*t')
  return string.format('%04d%02d%02d_%02d%02d%02d', t.year, t.month, t.day, t.hour, t.min, t.sec)
end

local function hasAce(src)
  if not Config.RequireAce then return true end
  if src == 0 then return true end -- console
  return IsPlayerAceAllowed(src, Config.AceName)
end

local function inList(list, value)
  for _, v in ipairs(list) do
    if v == value then return true end
  end
  return false
end

local function getExt(path)
  local ext = path:match('%.([%w]+)$')
  if not ext then return nil end
  return ext:lower()
end

local function safeSample(s)
  if not s then return '' end
  -- keep reports/webhooks ASCII-safe (avoid binary / invalid UTF-8 issues)
  s = s:gsub('[\r\n]', ' ')
  s = s:gsub('[%z\1-\8\11\12\14-\31]', '?')
  s = s:gsub('[\128-\255]', '?')
  return s
end


local function countFind(text, pat, plain)
  local n, init = 0, 1
  while true do
    local s, e = string.find(text, pat, init, plain == true)
    if not s then break end
    n = n + 1
    init = e + 1
  end
  return n
end

local function truncateBytes(s, maxBytes)
  if #s <= maxBytes then return s end
  return s:sub(1, maxBytes)
end

-- Heuristic rules:
-- NOTE: These are intentionally "noisy" and meant to flag things for human review.
local RULES = {
  {
    id = 'LUA_LOADSTRING',
    severity = 'critical',
    description = 'Dynamic code execution (loadstring/load) can be used to run fetched code',
    patterns = {
      { pat = 'loadstring%s*%(', plain = false },
      { pat = 'load%s*%(', plain = false }, -- Lua 5.2+ load(...)
      { pat = 'assert%s*%(%s*load', plain = false },
    }
  },
  {
    id = 'OS_EXEC',
    severity = 'critical',
    description = 'OS command execution / process spawning',
    patterns = {
      { pat = 'os%.execute', plain = true },
      { pat = 'io%.popen', plain = true },
      { pat = 'package%.loadlib', plain = true },
    }
  },
  {
    id = 'SUSPICIOUS_HTTP_SOURCES',
    severity = 'high',
    description = 'HTTP requests to common code-hosting/raw endpoints (review intent)',
    patterns = {
      { pat = 'PerformHttpRequest%s*%(', plain = false },
      { pat = 'http://pastebin%.com', plain = false },
      { pat = 'https://pastebin%.com', plain = false },
      { pat = 'raw%.githubusercontent%.com', plain = false },
      { pat = 'rentry%.co', plain = false },
      { pat = 'hastebin', plain = false },
    }
  },
  {
    id = 'DISCORD_WEBHOOK',
    severity = 'medium',
    description = 'Discord webhook usage (can be normal logging, can also be exfil)',
    patterns = {
      { pat = 'discord%.com/api/webhooks', plain = false },
      { pat = 'discordapp%.com/api/webhooks', plain = false },
    }
  },
  {
    id = 'LICENSEKEY_ACCESS',
    severity = 'high',
    description = 'Access to license keys or secrets via convars/environment',
    patterns = {
      { pat = "GetConvar%s*%(%s*['\"]sv_licenseKey['\"]", plain = false },
      { pat = "GetConvar%s*%(%s*['\"]steam_webApiKey['\"]", plain = false },
      { pat = "GetConvar%s*%(%s*['\"]mysql_connection_string['\"]", plain = false },
      { pat = "GetConvar%s*%(%s*['\"]txAdmin%w*['\"]", plain = false },
    }
  },
  {
    id = 'OBFUSCATION_HINTS',
    severity = 'medium',
    description = 'Possible obfuscation/minification indicators (review)',
    patterns = {
      { pat = 'string%.char%s*%(', plain = false },
      { pat = '%.%.%s*%.%.', plain = false }, -- repeated concatenation
      { pat = '(%w+)=%1', plain = false },    -- simple self-assign patterns (weak heuristic)
      { pat = 'local%s+_%w+', plain = false }, -- lots of underscore locals common in obfuscators
    }
  },
  {
    id = 'REMOTE_EVAL_JS',
    severity = 'high',
    description = 'JS: eval/new Function can run fetched code (if you have NUI)',
    patterns = {
      { pat = 'eval%(', plain = false },
      { pat = 'new%s+Function%(', plain = false },
    }
  },
  {
    id = 'AUTO_START_STOP_RESOURCES',
    severity = 'medium',
    description = 'Starts/stops other resources (can be admin tools, can be abuse)',
    patterns = {
      { pat = 'StartResource%s*%(', plain = false },
      { pat = 'StopResource%s*%(', plain = false },
      { pat = 'EnsureResource%s*%(', plain = false },
      { pat = [[ExecuteCommand%s*%(%s*['\"]restart]], plain = false },
    }
  },
}

local function shouldSuppress(finding)
  for _, pat in ipairs(Config.SuppressFindings or {}) do
    if finding.description:lower():find(pat:lower(), 1, true) then
      return true
    end
    if finding.id:lower():find(pat:lower(), 1, true) then
      return true
    end
  end
  return false
end

local function eligibleSeverity(sev)
  local min = Config.MinSeverity or 'low'
  return (severityRank[sev] or 1) >= (severityRank[min] or 1)
end


-- Limit certain rules to certain file types (extensions) to reduce false positives.
-- ext is lower-case (e.g., lua, js, html, json, cfg, txt, xml)
local RULE_SCOPE = {
  LUA_LOADSTRING = { lua = true },
  OS_EXEC = { lua = true },
  AUTO_START_STOP_RESOURCES = { lua = true },
  LICENSEKEY_ACCESS = { lua = true },

  REMOTE_EVAL_JS = { js = true, html = true },

  -- These can show up across languages/configs
  DISCORD_WEBHOOK = { lua = true, js = true, html = true, json = true, cfg = true, txt = true },
  SUSPICIOUS_HTTP_SOURCES = { lua = true, js = true, html = true, json = true, cfg = true, txt = true },
  OBFUSCATION_HINTS = { lua = true, js = true, html = true },
}

local function extractQuotedStrings(text)
  local out = {}
  local i, n = 1, #text
  while i <= n do
    local c = text:sub(i,i)
    if c == '"' or c == "'" then
      local quote = c
      i = i + 1
      local buf = {}
      while i <= n do
        local ch = text:sub(i,i)
        if ch == '\\' then
          -- skip escaped char
          if i < n then
            table.insert(buf, text:sub(i+1,i+1))
            i = i + 2
          else
            i = i + 1
          end
        elseif ch == quote then
          i = i + 1
          break
        else
          table.insert(buf, ch)
          i = i + 1
        end
      end
      local s = table.concat(buf)
      if s ~= '' then
        out[#out+1] = s
      end
    else
      i = i + 1
    end
  end
  return out
end

local function collectManifestFiles(resName)
  local candidates = {}

  local manifest = LoadResourceFile(resName, 'fxmanifest.lua')
  if not manifest then
    manifest = LoadResourceFile(resName, '__resource.lua')
  end

  if manifest then
    -- Extract quoted strings from manifest and keep those that look like file paths.
    local quoted = extractQuotedStrings(manifest)
    for _, q in ipairs(quoted) do
      local ext = getExt(q)
      if ext and (Config.ScanExtensions[ext] == true) then
        candidates[q] = true
      end
    end
  end

  -- Add some common entrypoints if they exist
  local common = {
    'fxmanifest.lua',
    '__resource.lua',
    'server.lua',
    'client.lua',
    'shared.lua',
    'config.lua',
    'main.lua',
    'init.lua',
    'server/server.lua',
    'client/client.lua',
    'shared/shared.lua',
    'html/index.html',
    'html/app.js',
    'html/script.js',
  }
  for _, p in ipairs(common) do
    candidates[p] = true
  end

  local out = {}
  for path, _ in pairs(candidates) do
    table.insert(out, path)
  end
  table.sort(out)
  return out
end

local function countFindInLine(line, pat, plain)
  local n, init = 0, 1
  while true do
    local s, e = string.find(line, pat, init, plain == true)
    if not s then break end
    n = n + 1
    init = e + 1
  end
  return n
end

local function splitLines(text)
  local lines = {}
  -- keep it simple; this is for line-based sampling and counts
  for line in string.gmatch(text, "([^\n]*)\n?") do
    table.insert(lines, line)
  end
  return lines
end

local function scanText(text, ext)
  local findings = {}
  local lines = splitLines(text)

  for _, rule in ipairs(RULES) do
    local scope = RULE_SCOPE[rule.id]
    if scope and (not ext or scope[ext] ~= true) then
      goto continue_rule
    end
    local hits = 0
    local samples = {}
    local maxSamples = tonumber(Config.MaxSamplesPerRulePerFile) or 3

    for lineNo, line in ipairs(lines) do
      local lineHits = 0
      for _, pat in ipairs(rule.patterns) do
        lineHits = lineHits + countFindInLine(line, pat.pat, pat.plain)
      end

      if lineHits > 0 then
        hits = hits + lineHits
        if #samples < maxSamples then
          table.insert(samples, {
            line = lineNo,
            text = safeSample(line:sub(1, 240)),
            hits = lineHits
          })
        end
      end
    end

    if hits > 0 and eligibleSeverity(rule.severity) then
      table.insert(findings, {
        id = rule.id,
        severity = rule.severity,
        description = rule.description,
        hits = hits,
        samples = samples,
      })
    end
    ::continue_rule::
  end

  return findings
end

local function readFileSafe(resName, relPath)
  local content = LoadResourceFile(resName, relPath)
  if not content then return nil end
  if Config.MaxFileBytes and #content > Config.MaxFileBytes then
    return truncateBytes(content, Config.MaxFileBytes)
  end
  return content
end

local function scanResource(resName)
  local files = collectManifestFiles(resName)
  local results = {
    resource = resName,
    scanned_files = 0,
    skipped_files = 0,
    findings = {},
    file_findings = {},
  }

  local scanned = 0
  for _, path in ipairs(files) do
    if scanned >= (Config.MaxFilesPerResource or 250) then
      results.skipped_files = results.skipped_files + 1
    else
      local ext = getExt(path)
      if ext and Config.ScanExtensions[ext] then
        local content = readFileSafe(resName, path)
        if content then
          scanned = scanned + 1
          results.scanned_files = results.scanned_files + 1

-- Yield periodically to reduce server thread hitches on large scans
local yieldEvery = tonumber(Config.YieldEveryFiles) or 0
if yieldEvery > 0 and (results.scanned_files % yieldEvery == 0) then
  Wait(tonumber(Config.YieldWaitMs) or 0)
end

          local f = scanText(content, ext)
          if #f > 0 then
            for _, one in ipairs(f) do
              if not shouldSuppress(one) then
                table.insert(results.findings, one)
              end
            end
            results.file_findings[path] = f
          end
        end
      end
    end
  end

  -- rollup counts by (id)
  local rollup = {}
  for _, f in ipairs(results.findings) do
    local k = f.id .. '|' .. f.severity
    rollup[k] = (rollup[k] or 0) + (f.hits or 1)
  end

  results.rollup = {}
  for k, hits in pairs(rollup) do
    local id, sev = k:match('^(.-)|(.+)$')
    table.insert(results.rollup, { id = id, severity = sev, hits = hits })
  end
  table.sort(results.rollup, function(a,b)
    if severityRank[a.severity] == severityRank[b.severity] then
      return a.id < b.id
    end
    return (severityRank[a.severity] or 1) > (severityRank[b.severity] or 1)
  end)

  return results
end

local function scanAll()
  local report = {
    tool = 'TwoPoint_AVScanner',
    version = GetResourceMetadata(GetCurrentResourceName(), 'version', 0) or 'unknown',
    generated_at = os.date('!%Y-%m-%dT%H:%M:%SZ'),
    server_name = GetConvar('sv_hostname', 'FiveM Server'),
    resources = {},
    summary = {
      resources_scanned = 0,
      resources_flagged = 0,
      findings_total = 0,
      by_severity = { low = 0, medium = 0, high = 0, critical = 0 },
    }
  }

  local n = GetNumResources()
  for i = 0, n - 1 do
    local res = GetResourceByFindIndex(i)
    if res and res ~= '' and not inList(Config.ExcludeResources or {}, res) then
      local r = scanResource(res)
      report.summary.resources_scanned = report.summary.resources_scanned + 1
      local yieldEveryRes = tonumber(Config.YieldEveryResources) or 0
      if yieldEveryRes > 0 and (report.summary.resources_scanned % yieldEveryRes == 0) then
        Wait(tonumber(Config.YieldWaitMs) or 0)
      end

      if #r.findings > 0 then
        report.summary.resources_flagged = report.summary.resources_flagged + 1
      end
      for _, f in ipairs(r.findings) do
        report.summary.findings_total = report.summary.findings_total + 1
        report.summary.by_severity[f.severity] = (report.summary.by_severity[f.severity] or 0) + 1
      end
      table.insert(report.resources, r)
    end
  end

  table.sort(report.resources, function(a,b)
    local ac = #a.findings
    local bc = #b.findings
    if ac == bc then return a.resource < b.resource end
    return ac > bc
  end)

  return report
end

local function printReport(report)
  print(('^3[AVSCAN]^7 Scan complete: %d resources scanned, %d flagged, %d findings total'):format(
    report.summary.resources_scanned,
    report.summary.resources_flagged,
    report.summary.findings_total
  ))

  for _, r in ipairs(report.resources) do
    if #r.findings > 0 then
      print(('^3[AVSCAN]^7 ^1%s^7 (%d finding(s), %d file(s) scanned)'):format(
        r.resource, #r.findings, r.scanned_files
      ))
      for _, x in ipairs(r.rollup or {}) do
        local color = '^2'
        if x.severity == 'medium' then color = '^3' end
        if x.severity == 'high' then color = '^1' end
        if x.severity == 'critical' then color = '^8' end
        print(('  %s- %s^7 (%s): %d hit(s)'):format(color, x.id, x.severity, x.hits))
      end
    end
  end
end

local function trySave(resName, relPath, payload)
  SaveResourceFile(resName, relPath, payload, -1)
  local check = LoadResourceFile(resName, relPath)
  return check ~= nil
end

local function saveReport(report)
  if not Config.SaveReport then return nil end
  local resName = GetCurrentResourceName()
  local fileName = ('avscan_%s.json'):format(nowStamp())
  local payload = json.encode(report, { indent = true })

  -- Try to create/use reports/ folder (some servers won't create nested folders via SaveResourceFile)
  SaveResourceFile(resName, 'reports/.keep', '', -1)

  local folderPath = ('reports/%s'):format(fileName)
  if trySave(resName, folderPath, payload) then
    return folderPath
  end

  -- Fallback: save in the resource root
  if trySave(resName, fileName, payload) then
    return fileName
  end

  -- Last resort: alternate name
  local alt = ('reports_%s'):format(fileName)
  SaveResourceFile(resName, alt, payload, -1)
  return alt
end


local function postDiscord(report, reportPath)
  if not Config.DiscordWebhook or Config.DiscordWebhook == '' then return end

  local summary = report.summary
  local lines = {
    ('**AV Scan Complete**'),
    ('Server: `%s`'):format(report.server_name),
    ('Resources scanned: **%d**'):format(summary.resources_scanned),
    ('Flagged: **%d**'):format(summary.resources_flagged),
    ('Findings: **%d**'):format(summary.findings_total),
    ('Severity: critical=%d, high=%d, medium=%d, low=%d'):format(
      summary.by_severity.critical or 0,
      summary.by_severity.high or 0,
      summary.by_severity.medium or 0,
      summary.by_severity.low or 0
    ),
  }
  if reportPath then
    table.insert(lines, ('Report saved: `%s` (on server filesystem)'):format(reportPath))
  end

  local embed = {
    title = 'TwoPoint_AVScanner',
    description = table.concat(lines, '\n'),
    color = 16753920,
  }

  PerformHttpRequest(Config.DiscordWebhook, function(code, body, headers) end, 'POST',
    json.encode({ username = 'AVScanner', embeds = { embed } }),
    { ['Content-Type'] = 'application/json' }
  )
end

local function runScan(src, scope, resName)
  local report
  if scope == 'one' and resName and resName ~= '' then
    report = {
      tool = 'TwoPoint_AVScanner',
      version = GetResourceMetadata(GetCurrentResourceName(), 'version', 0) or 'unknown',
      generated_at = os.date('!%Y-%m-%dT%H:%M:%SZ'),
      server_name = GetConvar('sv_hostname', 'FiveM Server'),
      resources = {},
      summary = {
        resources_scanned = 0,
        resources_flagged = 0,
        findings_total = 0,
        by_severity = { low = 0, medium = 0, high = 0, critical = 0 },
      }
    }

    local r = scanResource(resName)
    report.summary.resources_scanned = 1
    if #r.findings > 0 then report.summary.resources_flagged = 1 end
    for _, f in ipairs(r.findings) do
      report.summary.findings_total = report.summary.findings_total + 1
      report.summary.by_severity[f.severity] = (report.summary.by_severity[f.severity] or 0) + 1
    end
    table.insert(report.resources, r)
  else
    report = scanAll()
  end

  printReport(report)
  local saved = saveReport(report)
  postDiscord(report, saved)

  if src ~= 0 then
    local msg = ('AV scan complete: %d resources scanned, %d flagged, %d findings.'):format(
      report.summary.resources_scanned,
      report.summary.resources_flagged,
      report.summary.findings_total
    )
    TriggerClientEvent('chat:addMessage', src, { args = { '^3AVSCAN^7', msg } })
    if saved then
      TriggerClientEvent('chat:addMessage', src, { args = { '^3AVSCAN^7', 'Report saved to: ' .. saved } })
    end
  end
end

RegisterCommand('avscan', function(src, args)
  if not hasAce(src) then
    if src ~= 0 then
      TriggerClientEvent('chat:addMessage', src, { args = { '^3AVSCAN^7', '^1You do not have permission to run this.^7' } })
    end
    return
  end
  CreateThread(function()
    runScan(src, 'all')
  end)
end, false)

RegisterCommand('avscanres', function(src, args)
  if not hasAce(src) then
    if src ~= 0 then
      TriggerClientEvent('chat:addMessage', src, { args = { '^3AVSCAN^7', '^1You do not have permission to run this.^7' } })
    end
    return
  end
  local res = args[1]
  if not res or res == '' then
    if src ~= 0 then
      TriggerClientEvent('chat:addMessage', src, { args = { '^3AVSCAN^7', 'Usage: /avscanres <resourceName>' } })
    else
      print('[AVSCAN] Usage: avscanres <resourceName>')
    end
    return
  end
  if GetResourceState(res) == 'missing' then
    if src ~= 0 then
      TriggerClientEvent('chat:addMessage', src, { args = { '^3AVSCAN^7', '^1Resource not found:^7 ' .. res } })
    else
      print('[AVSCAN] Resource not found: ' .. res)
    end
    return
  end
  CreateThread(function()
    runScan(src, 'one', res)
  end)
end, false)

-- Exported API (server-side): exports['TwoPoint_AVScanner']:scan() or :scanResource('name')
exports('scan', function()
  return scanAll()
end)

exports('scanResource', function(resName)
  return scanResource(resName)
end)


