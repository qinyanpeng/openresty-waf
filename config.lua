--WAF config file,开："on",关："off"

--waf 总开关
config_waf_enable = "on"
--日志目录
config_log_dir = "/tmp"
--rule setting
config_rule_dir = "/usr/local/openresty/nginx/conf/waf/rule-config"
--url白名单开关
config_white_url_check = "off"
--ip白名单开关
config_white_ip_check = "off"
--ip黑名单开关
config_black_ip_check = "on"
--url过滤器开关
config_url_check = "off"
--url args 过滤器开关
config_url_args_check = "off"
--user_agent过滤器开关
config_user_agent_check = "off"
--cookie过滤器开关
config_cookie_check = "off"

--cc开关
config_cc_check = "off"
--cc频率设定，次数/时间（单位s）
config_cc_rate = "100/60"

--cc_ip_check开关
config_cc_ip_check = "off"
--触发阀值，ip将被加入config_black_ip_check，永远封禁。
config_cc_ip_rate = "50/5"

--post内容过滤开关
config_post_check = "off"

--ip所属国家/省份地区位置过滤开关
config_white_country_check = "off"

--返回内容redirect/html
config_waf_output = "html"
--跳转的url地址
config_waf_redirect_url = "www.ipsv.cn"
--返回html内容
config_output_html=[[
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta http-equiv="Content-Language" content="zh-cn" />
<title>Have a rest</title>
</head>
<body>
<h1 align="center"> 喝口水歇歇吧，您已触发防火墙。
</body>
</html>
]]

