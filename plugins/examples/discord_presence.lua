-- @name Discord Presence
-- @version 2.1
-- @author Euphoria
-- @description Shows Euphoria, the open file's name, and the current tab on your Discord profile.
-- @permissions discord

local APPLICATION_ID = "1567508667090214942"
local LOGO = "https://raw.githubusercontent.com/JoeyKoch1/euphoria-re/main/logo.jpg"
local RETRY_SECONDS = 15

local hide_name = false
local needs_update = true
local waited = RETRY_SECONDS

local function is_connected(status)
    return string.sub(status, 1, 9) == "connected"
end

local function update()
    local binary = euphoria.binary()
    local file = "No file open"
    if binary ~= nil then
        file = hide_name and "Reading a file" or binary.name
    end

    euphoria.discord.set_activity({
        details = file,
        state = "Tab: " .. euphoria.tab(),
        large_image = LOGO,
        large_text = "Euphoria",
        started = true,
    })
    needs_update = false
end

euphoria.on("binary_opened", function()
    needs_update = true
end)

euphoria.on("tab_changed", function()
    needs_update = true
end)

euphoria.on("tick", function()
    local status = euphoria.discord.status()
    if is_connected(status) then
        if needs_update then
            update()
        end
    elseif status ~= "connecting" then
        waited = waited + 1
        if waited >= RETRY_SECONDS then
            waited = 0
            needs_update = true
            euphoria.discord.connect(APPLICATION_ID)
        end
    end
end)

euphoria.add_tab("Discord", function(ui)
    ui:heading("Discord Presence")
    ui:label("Status: " .. euphoria.discord.status())

    local hide = ui:checkbox("hide_name", "Hide the file name on my profile")
    if hide ~= hide_name then
        hide_name = hide
        needs_update = true
    end
end)
