Config = {}

-- Run a scan automatically on server start (recommended: false on large servers)
Config.RunOnStart = true
Config.RunOnStartDelayMs = 15000

-- Permission (ACE) required to run commands (recommended: true)
-- Grant with: add_ace group.admin avscanner.scan allow
Config.RequireAce = false
Config.AceName = 'avscanner.scan'

-- Resources to exclude from scanning
Config.ExcludeResources = {
  -- this resource
  'TwoPoint_AVScanner',
  -- common system/framework resources you may want to skip
  'sessionmanager',
  'spawnmanager',
  'hardcap',
  'baseevents',
  'chat',
  'connectqueue',
}

-- File extensions we scan (manifest-discovered + common defaults)
Config.ScanExtensions = {
  ['lua'] = true,
  ['js'] = true,
  ['html'] = true,
  ['css'] = true,
  ['json'] = true,
  ['cfg'] = true,
  ['txt'] = true,
  ['xml'] = true,
}

-- Limit how many files per resource to scan (safety)
Config.MaxFilesPerResource = 250
Config.MaxFileBytes = 1024 * 1024 * 2 -- 2MB per file

-- Performance: yield periodically to avoid server thread hitches on large servers
Config.YieldEveryFiles = 25
Config.YieldEveryResources = 10  -- yield after this many resources scanned (0 disables)     -- yield after this many files scanned (0 disables)
Config.YieldWaitMs = 0          -- Wait() duration when yielding

-- For reports: store up to N example lines per rule per file
Config.MaxSamplesPerRulePerFile = 3


-- Save a JSON report into this resource's reports/ folder
Config.SaveReport = true

-- Optional: send summary to a Discord webhook
Config.DiscordWebhook = 'https://discord.com/api/webhooks/1455350293742227547/7CC1d28HeTuRF-qjfERWBCT_Kn8VUKEDTqGlxho5jEw8reeqjrA8i_G5NJTVMLnlk-Jf' -- e.g. https://discord.com/api/webhooks/...

-- If set, only show findings at or above this severity: 'low'|'medium'|'high'|'critical'
Config.MinSeverity = 'low'

-- Optional allow-list: patterns (Lua patterns) that, if matched on a finding description/id,
-- will suppress it (use carefully)
Config.SuppressFindings = {
  -- Example:
  -- 'discord webhook for logging', -- suppress descriptions that match this pattern
}
