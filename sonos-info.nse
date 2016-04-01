description = [[
Extracts and outputs Sonos info
]]

---
-- @usage nmap -p1400 --script sonos-info.nse <host>
--
-- This script uses patterns to extract useful Sonos info from HTTP/XML
-- responses and writes these to the output.
--
-- @output
-- PORT     STATE SERVICE       REASON
-- 1400/tcp open  cadkey-tablet syn-ack
-- | http-sonos:
-- |   modelNumber: S0
-- |   modelName: Sonos ProductName
-- |   modelDescription: Sonos ProductDescription
-- |   HardwareVersion: 0.0.0.0-0
-- |   IPAddress: 000.000.000.000
-- |   ZoneName: Room
-- |   MACAddress: 00:00:00:00:00:00
-- |   LocalUID: RINCON_00000000000000000
-- |   ExtraInfo: OTP: 0.00.0(0-00-0-zp0s-0.0)
-- |   SoftwareVersion: 00.0-00000
-- |_  SerialNumber: 00--00-00-00-00:00
-- 
---

categories = {"discovery", "safe"}
author = "Barry Caruth"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"
local string = require "string"

-- Patterns to find useful Sonos information in XML response
xml_patterns = {
    "<ZoneName>.-</ZoneName>",
    "<LocalUID>.-</LocalUID>",
    "<SerialNumber>.-</SerialNumber>",
    "<SoftwareVersion>.-</SoftwareVersion>",
    "<HardwareVersion>.-</HardwareVersion>",
    "<IPAddress>.-</IPAddress>",
    "<MACAddress>.-</MACAddress>",
    "<ExtraInfo>.-</ExtraInfo>",
    "<modelNumber>.-</modelNumber>",
    "<modelDescription>.-</modelDescription>",
    "<modelName>.-</modelName>"
    }

-- Only run on devices listening on the Sonos web UI port
portrule = shortport.port_or_service( 1400, "http", "tcp", "open")

action = function(host, port)

    local info = {}
  
    -- Lua's abbreviated patterns support doesn't have a fixed-number-of-repetitions syntax.
    for i, pattern in ipairs(xml_patterns) do
      xml_patterns[i] = xml_patterns[i]
    end
  
    local index, target, response 
    local body = {}
    
    -- Get the status page to determine the Sonos device type
    target = "/status"
    response = http.get(host, port, target)

    if response.body then
    
      -- get info URL which varies depending on whether a Sonos bridge/boost or player
      target = string.match ( response.body, "(/status/z[lp])")

      -- get info content and store in table
      response = http.get(host, port, target)
      if response.body then
        body["info"] = response.body
      end
     
      -- get device description content and store in table
      target = "/xml/device_description.xml"
      response = http.get(host, port, target)
      if response.body then
        body["desc"] = response.body
      end

      if next(body) then

          -- loop through all responses
          for j, response in pairs(body) do

            -- debug output          
            stdnse.print_debug(1, "Response: %s", response )
                          
            -- retrive info from XML response using patterns
            for i, pattern in ipairs(xml_patterns) do
                
                stdnse.print_debug(1, "Pattern: %s", pattern )
                                  
                -- assume zero or one match for each patterm
                local c = string.match(response, pattern)
  
                -- check we got a match to parse
                if c then
                    
                  -- parse XML node to separate attribute from value  
                  local attribute, value = string.match (c, '^<(.-)>(.-)</.->$')
                  
                  -- optional debug output
                  stdnse.print_debug(1, "Raw XML: %s", c )
                  stdnse.print_debug(1, "Attribute: %s", attribute)
                  stdnse.print_debug(1, "Value: %s", value)
    
                  -- store result in info table 
                  if attribute then
                    info[attribute] = value
                  end
                
                end -- of match parse
                
            end -- of pattern loop
            
            -- if we got something then increment counter
            if (index) then
              index = index + 1
            else
              index = 1
            end
          end

        end -- of body loop
    end -- of status check

  -- If the table is empty.
  if next(info) == nil then
    return "Couldn't find any Sonos info."
  end

  -- return results table
  return info

end