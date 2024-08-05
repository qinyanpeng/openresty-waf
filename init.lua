local geoip = require "geoip"
--WAF Action
require 'config'
require 'lib'

--args
local rulematch = ngx.re.find
local unescape = ngx.unescape_uri


--allow country. if whitecountry.rule is null,allow all.
function white_country_check()
    if config_white_country_check == "on" then
        local COUNTRY_WHITE_RULE = get_rule('whitecountry.rule')
        local CLIENT_IP = get_client_ip()
        local result = geoip.lookup_addr(CLIENT_IP)
        if COUNTRY_WHITE_RULE ~= nil and result and CLIENT_IP then
            local bl = false
            for _,rule in pairs(COUNTRY_WHITE_RULE) do
                if rule ~= "" and rulematch(result.country_code,rule,"jo") then
                    return true
                end
            end
            if config_waf_enable == "on" then
                log_record('White_COUNTRY',ngx.var_request_uri,"-",result.country_code,'deny')
                ngx.exit(423)
                return true
            else
                log_record('White_COUNTRY',ngx.var_request_uri,"-",result.country_code,'monitor')
            end
        end
    end
end

--allow white ip
function white_ip_check()
    if config_white_ip_check == "on" then
        local IP_WHITE_RULE = get_rule('whiteip.rule')
        local WHITE_IP = get_client_ip()
        if IP_WHITE_RULE ~= nil then
            for _,rule in pairs(IP_WHITE_RULE) do
                if rule ~= "" and rulematch(WHITE_IP,rule,"jo") then
                    log_record('White_IP',ngx.var_request_uri,"-","-","-")
                    return true
                end
            end
        end
    end
end

--deny black ip
function black_ip_check()
     if config_black_ip_check == "on" then
        local IP_BLACK_RULE = get_rule('blackip.rule')
        local BLACK_IP = get_client_ip()
        if IP_BLACK_RULE ~= nil then
            for _,rule in pairs(IP_BLACK_RULE) do
                if rule ~= "" and rulematch(BLACK_IP,rule,"jo") then
                    if config_waf_enable == "on" then
                        log_record('BlackList_IP',ngx.var_request_uri,"_","_","deny")
                        ngx.exit(423)
                        return true
                    else
                        log_record('BlackList_IP',ngx.var_request_uri,"-","-","monitor")
                    end
                end
            end
        end
    end
end

--allow white url
function white_url_check()
    if config_white_url_check == "on" then
        local URL_WHITE_RULES = get_rule('whiteurl.rule')
        local REQ_URI = ngx.var.request_uri
        if URL_WHITE_RULES ~= nil then
            for _,rule in pairs(URL_WHITE_RULES) do
                if rule ~= "" and rulematch(REQ_URI,rule,"jo") then
                    return true
                end
            end
        end
    end
end

--cc攻击，限定频次访问，超出频次拒绝。
function cc_attack_check()
    if config_cc_check == "on" then
        local ATTACK_URI=ngx.var.uri
        local CC_TOKEN = get_client_ip()..ATTACK_URI
        local limit = ngx.shared.limit
        CCcount=tonumber(string.match(config_cc_rate,'(.*)/'))
        CCseconds=tonumber(string.match(config_cc_rate,'/(.*)'))
        local req,_ = limit:get(CC_TOKEN)
        if req then
            if req > CCcount then
                if config_waf_enable == "on" then
                    log_record('CC_Attack',ngx.var.request_uri,"-","-","deny")
                    ngx.exit(423)
                else
                    log_record('CC_Attack',ngx.var.request_uri,"-","-","monitor")
                end
            else
                limit:incr(CC_TOKEN,1)
            end
        else
            limit:set(CC_TOKEN,1,CCseconds)
        end
    end
    return false
end


--cc攻击。触发阀值，ip将被加入black_ip_check黑名单。
function cc_ip_attack_check()
    if config_cc_ip_check == "on" then
        local client_ip = get_client_ip()
        local ATTACK_URI=ngx.var.uri
        local limit = ngx.shared.limit
        for CC_IP in string.gmatch(client_ip, '%d+.%d+.%d+.%d+') do
            local CC_TOKEN = CC_IP..ATTACK_URI
            CCIPcount=tonumber(string.match(config_cc_ip_rate,'(.*)/'))
            CCIPseconds=tonumber(string.match(config_cc_ip_rate,'/(.*)'))
            local req,_ = limit:get(CC_TOKEN)
            if req then
                if req > CCIPcount then
                    if config_waf_enable == "on" then
                        set_blackip_rule(CC_IP)
                        log_record('CC_IP_Attack',ngx.var.request_uri,"-",CC_TOKEN,"AddBlackList")
                        ngx.exit(423)
                    else
                        log_record('CC_IP_Attack',ngx.var.request_uri,"-",CC_TOKEN,"monitor")
                    end
                else
                    limit:incr(CC_TOKEN,1)
                end
            else
                limit:set(CC_TOKEN,1,CCIPseconds)
            end
        end
    end
    return false
end

--deny cookie
function cookie_attack_check()
    if config_cookie_check == "on" then
        local COOKIE_RULES = get_rule('cookie.rule')
        local USER_COOKIE = ngx.var.http_cookie
        if USER_COOKIE ~= nil then
            for _,rule in pairs(COOKIE_RULES) do
                if rule ~="" and rulematch(USER_COOKIE,rule,"jo") then
                    log_record('Deny_Cookie',ngx.var.request_uri,"-",rule,"-")
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
             end
	 end
    end
    return false
end

--deny url
function url_attack_check()
    if config_url_check == "on" then
        local URL_RULES = get_rule('url.rule')
        local REQ_URI = ngx.var.request_uri
        for _,rule in pairs(URL_RULES) do
            if rule ~="" and rulematch(REQ_URI,rule,"jo") then
                log_record('Deny_URL',REQ_URI,"-",rule,"-")
                if config_waf_enable == "on" then
                    waf_output()
                    return true
                end
            end
        end
    end
    return false
end

--deny url args
function url_args_attack_check()
    if config_url_args_check == "on" then
        local ARGS_RULES = get_rule('args.rule')
        for _,rule in pairs(ARGS_RULES) do
            local REQ_ARGS = ngx.req.get_uri_args()
            for key, val in pairs(REQ_ARGS) do
                if type(val) == 'table' then
                    ARGS_DATA = table.concat(val, " ")
                else
                    ARGS_DATA = val
                end
                if ARGS_DATA and type(ARGS_DATA) ~= "boolean" and rule ~="" and rulematch(unescape(ARGS_DATA),rule,"jo") then
                    log_record('Deny_URL_Args',ngx.var.request_uri,"-",rule,"-")
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end
--deny user agent
function user_agent_attack_check()
    if config_user_agent_check == "on" then
        local USER_AGENT_RULES = get_rule('useragent.rule')
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil then
            for _,rule in pairs(USER_AGENT_RULES) do
                if rule ~="" and rulematch(USER_AGENT,rule,"jo") then
                    log_record('Deny_USER_AGENT',ngx.var.request_uri,"-",rule,"-")
                    if config_waf_enable == "on" then
                        waf_output()
                        return true
                    end
                end
            end
        end
    end
    return false
end

--deny post
function post_attack_check()
    if config_post_check == "on" then
        local POST_RULES = get_rule('post.rule')
        for _,rule in pairs(ARGS_RULES) do
            local POST_ARGS = ngx.req.get_post_args()
        end
        return true
    end
    return false
end

