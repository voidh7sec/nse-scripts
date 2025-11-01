local http = require "http"
local stdnse = require "stdnse"
local shortport = require "shortport"

description = [[
Basic brute force directory discovery.
Performs HTTP requests to common directories and reports findings.
]]

author = "voidh7"
license = "MIT"
categories = {"discovery", "safe"}


portrule = shortport.http

action = function(host, port)
    local results = {}

    local paths = {
        "/admin", "/api", "/backup", "/config", "/database",
        "/doc", "/docs", "/test", "/tmp", "/upload", "/download",
        "/images", "/js", "/css", "/includes", "/logs", "/sql",
        "/phpmyadmin", "/wp-admin", "/administrator", "/webadmin"
    }


    local options = {
        header = {
            ["User-Agent"] = "Mozilla/5.0 (compatible; Nmap Scripting Engine)"
        }
    }

    for _, path in ipairs(paths) do
        local response = http.get(host, port, path, options)
        if response and response.status then
            if response.status == 200 then
                table.insert(results, ("[200 OK] %s"):format(path))
            elseif response.status == 301 or response.status == 302 then
                local location = response.header and response.header.location or "unknown"
                table.insert(results, ("[%d Redirect] %s -> %s"):format(response.status, path, location))
            elseif response.status == 403 then
                table.insert(results, ("[403 Forbidden] %s"):format(path))
            elseif response.status == 401 then
                table.insert(results, ("[401 Unauthorized] %s"):format(path))
            end
        else
            table.insert(results, ("[ERROR] Failed to request: %s"):format(path))
        end

        stdnse.sleep(0.1)
    end

    if #results > 0 then
        return stdnse.format_output(true, results)
    else
        return "No interesting directories found"
    end
end
