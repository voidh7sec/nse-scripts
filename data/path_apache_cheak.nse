description = [[microscan of sensitive files in Apache]]
author = "voidh7"
license = "MIT"
categories = {"safe","discovery"}

portrule = function(host,port)
        return port.number == 80 and port.state == "open"
end

action = function(host,port)
        http = require "http"
        local results =  {}
        local paths = {
"/.htaccess",
"/.htpasswd",
"/httpd.conf",
"/apache2.conf",
"/.user.ini",
"/ssl.conf",
"/vhosts.conf"
        }

        for i,path in ipairs(paths) do
                local response = http.get(host,port,path)
                if response.status == 200 then
                        table.insert(results,"found:"..path)
                end
        end
        if #results > 0 then
                return table.concat(results,"\n")

        else
                return "[*]no sensitive files found"
        end

end
