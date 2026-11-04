-- @name Hello Tab
-- @version 1.0
-- @author Euphoria
-- @description Adds a tab that shows facts about the open file.

euphoria.add_tab("Hello", function(ui)
    ui:heading("Hello from Lua")

    local binary = euphoria.binary()
    if binary == nil then
        ui:label("Open a binary and its details show up here.")
        return
    end

    ui:table({ "Field", "Value" }, {
        { "File", binary.name },
        { "Architecture", binary.arch },
        { "Bytes", tostring(binary.size) },
        { "Routines", tostring(#euphoria.functions()) },
        { "SHA-256", binary.sha256 },
    })

    if ui:button("Jump to the entry point") then
        euphoria.jump(binary.entry)
    end
end)
