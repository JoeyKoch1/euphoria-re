-- @name Rename By Pattern
-- @version 1.0
-- @author Euphoria
-- @description Renames every routine whose symbol contains a piece of text.

euphoria.add_tab("Rename By Pattern", function(ui)
    local needle = ui:input("needle", "Text in the current name, such as alloc")
    local prefix = ui:input("prefix", "New name prefix")
    if needle == "" or prefix == "" then
        ui:label("Fill in both fields to see how many routines match.")
        return
    end

    local matches = {}
    for _, routine in ipairs(euphoria.functions()) do
        local name = routine.name or ""
        if string.find(name, needle, 1, true) then
            matches[#matches + 1] = routine
        end
    end

    ui:label(#matches .. " routine(s) contain \"" .. needle .. "\"")
    if #matches > 0 and ui:button("Rename them") then
        for _, routine in ipairs(matches) do
            euphoria.rename(routine.va, prefix .. "_" .. string.format("%x", routine.va))
        end
        euphoria.status("Renamed " .. #matches .. " routine(s)")
    end
end)
