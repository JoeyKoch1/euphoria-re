-- @name String Search
-- @version 1.0
-- @author Euphoria
-- @description Adds a tab for finding strings and the code that uses them.

local MAX_RESULTS = 200

euphoria.add_tab("String Search", function(ui)
    local query = ui:input("query", "Text to find")
    if query == "" then
        ui:label("Type something to search this file's strings.")
        return
    end

    local rows = {}
    local needle = string.lower(query)
    for _, entry in ipairs(euphoria.strings()) do
        if string.find(string.lower(entry.value), needle, 1, true) then
            local uses = #euphoria.xrefs_to(entry.va)
            rows[#rows + 1] = { string.format("0x%x", entry.va), tostring(uses), entry.value }
            if #rows == MAX_RESULTS then
                break
            end
        end
    end

    ui:label(#rows .. " found")
    ui:table({ "VA", "Used by", "Text" }, rows)
end)
