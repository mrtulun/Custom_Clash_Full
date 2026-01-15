/*
 基于 powerfullz 风格修改的订阅转换脚本
 适配业务分流与智能/手动组切换
 
 支持的传入参数：
 - smart: 启用智能选路 (默认 false)
 - ipv6: 启用 IPv6 支持 (默认 false)
 - full: 输出完整内核配置 (默认 false)
*/

const PROXY_GROUPS = {
    DIRECT: "直连",
    REJECT: "拒绝",
    ALL_SMART: "所有-智选",
    ALL_MANUAL: "所有-手选",
    ABROAD: "国外",
    DOMESTIC: "国内",
    OTHER: "其他"
};

const REGEX = {
    JP: "广日|日本|JP|川日|东京|大阪|泉日|jp|沪日|深日|🇯🇵|Japan",
    SG: "广新|新加坡|SG|sg|狮城|🇸🇬|Singapore",
    KR: "广韩|韩国|韓國|KR|首尔|春川|🇰🇷|Korea",
    US: "广美|US|美国|纽约|波特兰|达拉斯|俄勒|凤凰城|费利蒙|洛杉|圣何塞|圣克拉|西雅|芝加|🇺🇸|United States",
    OTHER_EXCLUDE: "直连|拒绝|广港|香港|HK|广台|台湾|广日|日本|广新|新加坡|广韩|韩国|广美|美国|英国|UK"
};

// --- 辅助工具函数 ---
function parseBool(value) {
    if (typeof value === "boolean") return value;
    if (typeof value === "string") return value.toLowerCase() === "true" || value === "1";
    return false;
}

const buildList = (...elements) => elements.flat().filter(Boolean);

/**
 * 解析传入参数
 */
function buildFeatureFlags(args) {
    return {
        smartEnabled: parseBool(args.smart),
        ipv6Enabled: parseBool(args.ipv6),
        fullConfig: parseBool(args.full)
    };
}

const rawArgs = typeof $arguments !== 'undefined' ? $arguments : {};
const { smartEnabled, ipv6Enabled, fullConfig } = buildFeatureFlags(rawArgs);

// --- 配置组件构建 ---

const ruleProviders = {
    "ChatGPT": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://gh-proxy.com/github.com/metacubex/meta-rules-dat/raw/refs/heads/meta/geo/geosite/openai.mrs" },
    "Claude": { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gh-proxy.com/raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Claude/Claude.list" },
    "Telegram_IP": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://gh-proxy.com/github.com/metacubex/meta-rules-dat/raw/refs/heads/meta/geo/geoip/telegram.mrs" },
    "China_Domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://gh-proxy.com/github.com/metacubex/meta-rules-dat/raw/refs/heads/meta/geo/geosite/cn.mrs" },
    "China_IP": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://gh-proxy.com/github.com/metacubex/meta-rules-dat/raw/refs/heads/meta/geo/geoip/cn.mrs" }
    // ... 其他 Provider 可按此格式继续添加
};

function buildRules() {
    return [
        "RULE-SET,ChatGPT,ChatGPT",
        "RULE-SET,Claude,Claude",
        "RULE-SET,Telegram_IP,Telegram",
        "RULE-SET,China_Domain,国内",
        "GEOIP,CN,国内,no-resolve",
        "MATCH,其他"
    ];
}

function buildDnsConfig() {
    return {
        "enable": true,
        "ipv6": ipv6Enabled,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.20.0.1/16",
        "nameserver": ["223.5.5.5"],
        "fake-ip-filter": ["+.lan", "+.local", "geosite:cn"]
    };
}

/**
 * 构建地区组模板
 */
function createRegionGroups(name, filterRegex) {
    const groups = [
        {
            "name": `${name}-故转`,
            "type": "fallback",
            "url": "https://cp.cloudflare.com/generate_204",
            "interval": 300,
            "proxies": [`${name}-手选`, `${name}-智选`]
        },
        {
            "name": `${name}-手选`,
            "type": "select",
            "include-all": true,
            "filter": filterRegex
        },
        {
            "name": `${name}-智选`,
            "type": "smart",
            "include-all": true,
            "interval": 300,
            "filter": filterRegex
        }
    ];
    return groups;
}

function buildProxyGroups() {
    // 基础代理池
    const baseProxies = [
        PROXY_GROUPS.DIRECT,
        PROXY_GROUPS.ALL_SMART,
        PROXY_GROUPS.ALL_MANUAL,
        "日本-故转",
        "新加坡-故转",
        "韩国-故转",
        "美国-故转",
        "其他-故转",
        PROXY_GROUPS.REJECT
    ];

    // 业务分流组名称列表
    const serviceNames = [
        "ChatGPT", "Gemini", "Copilot", "Perplexity", "Claude", "Meta AI",
        "GitHub", "Reddit", "Telegram", "WhatsApp", "Facebook", "YouTube",
        "TikTok", "Netflix", "HBO", "Disney", "Amazon", "Crunchyroll",
        "Spotify", "Nvidia", "Steam", "Games", "Crypto", "Apple", "Google",
        "Microsoft", "Test", "Block", "国外", "国内", "其他"
    ];

    const groups = [];

    // 1. 生成业务分流组
    serviceNames.forEach(name => {
        groups.push({
            "name": name,
            "type": "select",
            "proxies": baseProxies
        });
    });

    // 2. 所有节点池
    groups.push({
        "name": PROXY_GROUPS.ALL_MANUAL,
        "type": "select",
        "include-all": true,
        "filter": "^((?!(直连|拒绝)).)*$"
    });
    groups.push({
        "name": PROXY_GROUPS.ALL_SMART,
        "type": "smart",
        "include-all": true,
        "interval": 300,
        "filter": "^((?!(直连|拒绝)).)*$"
    });

    // 3. 地区组
    groups.push(...createRegionGroups("日本", REGEX.JP));
    groups.push(...createRegionGroups("新加坡", REGEX.SG));
    groups.push(...createRegionGroups("韩国", REGEX.KR));
    groups.push(...createRegionGroups("美国", REGEX.US));
    groups.push(...createRegionGroups("其他", `^((?!(${REGEX.OTHER_EXCLUDE})).)*$`));

    return groups;
}

// --- 主函数 ---
function main(config) {
    const resultConfig = { proxies: config.proxies };

    const proxyGroups = buildProxyGroups();
    const finalRules = buildRules();

    if (fullConfig) {
        Object.assign(resultConfig, {
            "port": 7890,
            "socks-port": 7891,
            "mixed-port": 7893,
            "allow-lan": true,
            "mode": "rule",
            "log-level": "info",
            "tun": {
                "enable": true,
                "stack": "gvisor",
                "auto-route": false
            }
        });
    }

    Object.assign(resultConfig, {
        "proxy-groups": proxyGroups,
        "rule-providers": ruleProviders,
        "rules": finalRules,
        "dns": buildDnsConfig(),
        "profile": { "store-selected": true, "store-fake-ip": true }
    });

    return resultConfig;
}
