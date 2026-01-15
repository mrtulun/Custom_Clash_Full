/*
 * 业务定制订阅转换脚本 (Mihomo/Smart 内核适配版)
 * * 参数说明:
 * - smart: 是否启用 smart 策略组 (默认 true, false 则回退到 url-test)
 * - full: 是否输出完整内核全局配置 (默认 false)
 * - ipv6: 是否开启 IPv6 (默认 false)
 */

// --- 1. 常量与配置定义 ---
const NODE_SUFFIX = ""; 

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
    JP: /广日|日本|JP|川日|东京|大阪|泉日|jp|沪日|深日|🇯🇵|Japan/i,
    SG: /广新|新加坡|SG|sg|狮城|🇸🇬|Singapore/i,
    KR: /广韩|韩国|韓國|KR|首尔|春川|🇰🇷|Korea/i,
    US: /广美|US|美国|纽约|波特兰|达拉斯|俄勒|凤凰城|费利蒙|洛杉|圣何塞|圣克拉|西雅|芝加|🇺🇸|United States/i,
    // 其他组排除掉上述已有的地区
    OTHER_EXCLUDE: /直连|拒绝|广港|香港|HK|广台|台湾|日本|JP|新加坡|SG|韩国|KR|美国|US/i
};

// --- 2. 辅助工具函数 ---
function parseBool(value, defaultValue) {
    if (typeof value === "boolean") return value;
    if (typeof value === "string") return value.toLowerCase() === "true" || value === "1";
    return defaultValue;
}

const buildList = (...elements) => elements.flat().filter(Boolean);

function buildFeatureFlags(args) {
    return {
        smartEnabled: parseBool(args.smart, true),
        fullConfig: parseBool(args.full, false),
        ipv6Enabled: parseBool(args.ipv6, false)
    };
}

// --- 3. 配置组件构建 ---

const ruleProviders = {
    "ChatGPT": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://gh-proxy.com/github.com/metacubex/meta-rules-dat/raw/refs/heads/meta/geo/geosite/openai.mrs" },
    "Claude": { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gh-proxy.com/raw.githubusercontent.com/blackmatrix7/ios_rule_script/refs/heads/master/rule/Clash/Claude/Claude.list" },
    "MetaAi": { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gh-proxy.com/raw.githubusercontent.com/liandu2024/clash/refs/heads/main/list/MetaAi.list" },
    "Perplexity": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://gh-proxy.com/github.com/metacubex/meta-rules-dat/raw/refs/heads/meta/geo/geosite/perplexity.mrs" },
    "Copilot": { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gh-proxy.com/raw.githubusercontent.com/liandu2024/clash/refs/heads/main/list/Copilot.list" },
    "Gemini": { type: "http", behavior: "classical", format: "text", interval: 86400, url: "https://gh-proxy.com/raw.githubusercontent.com/liandu2024/clash/refs/heads/main/list/Gemini.list" },
    "Telegram_Domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://gh-proxy.com/github.com/metacubex/meta-rules-dat/raw/refs/heads/meta/geo/geosite/telegram.mrs" },
    "Telegram_IP": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://gh-proxy.com/github.com/metacubex/meta-rules-dat/raw/refs/heads/meta/geo/geoip/telegram.mrs" },
    "Netflix_Domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://gh-proxy.com/github.com/metacubex/meta-rules-dat/raw/refs/heads/meta/geo/geosite/netflix.mrs" },
    "China_Domain": { type: "http", behavior: "domain", format: "mrs", interval: 86400, url: "https://gh-proxy.com/github.com/metacubex/meta-rules-dat/raw/refs/heads/meta/geo/geosite/cn.mrs" },
    "China_IP": { type: "http", behavior: "ipcidr", format: "mrs", interval: 86400, url: "https://gh-proxy.com/github.com/metacubex/meta-rules-dat/raw/refs/heads/meta/geo/geoip/cn.mrs" }
};

function buildRules() {
    return [
        "RULE-SET,ChatGPT,ChatGPT",
        "RULE-SET,Claude,Claude",
        "RULE-SET,MetaAi,Meta AI",
        "RULE-SET,Perplexity,Perplexity",
        "RULE-SET,Copilot,Copilot",
        "RULE-SET,Gemini,Gemini",
        "RULE-SET,Telegram_Domain,Telegram",
        "RULE-SET,Telegram_IP,Telegram",
        "RULE-SET,Netflix_Domain,Netflix",
        "RULE-SET,China_Domain,国内",
        "RULE-SET,China_IP,国内,no-resolve",
        "GEOIP,CN,国内,no-resolve",
        "MATCH,其他"
    ];
}

function buildDnsConfig(ipv6) {
    return {
        "enable": true,
        "ipv6": ipv6,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.20.0.1/16",
        "nameserver": ["223.5.5.5"],
        "fake-ip-filter": ["+.lan", "+.local", "geosite:cn"]
    };
}

// --- 4. 主转换函数 ---

function main(config) {
    const rawArgs = typeof $arguments !== 'undefined' ? $arguments : {};
    const { smartEnabled, fullConfig, ipv6Enabled } = buildFeatureFlags(rawArgs);

    const allProxies = (config.proxies || []).map(p => p.name);
    if (allProxies.length === 0) return config;

    // 辅助过滤函数
    const filterBy = (regex) => {
        const list = allProxies.filter(name => regex.test(name));
        return list.length > 0 ? list : [PROXY_GROUPS.DIRECT];
    };

    // 构建地区组函数
    const createRegionGroups = (regionName, regex) => {
        const nodes = filterBy(regex);
        return [
            {
                name: `${regionName}-故转`,
                type: "fallback",
                url: "https://cp.cloudflare.com/generate_204",
                interval: 300,
                proxies: [`${regionName}-手选`, `${regionName}-智选`]
            },
            {
                name: `${regionName}-手选`,
                type: "select",
                proxies: nodes
            },
            {
                name: `${regionName}-智选`,
                type: smartEnabled ? "smart" : "url-test",
                proxies: nodes,
                url: "https://cp.cloudflare.com/generate_204",
                interval: 300
            }
        ];
    };

    // 基础代理池 (供业务分流组使用)
    const baseSelectorProxies = [
        PROXY_GROUPS.DIRECT,
        PROXY_GROUPS.ALL_SMART,
        PROXY_GROUPS.ALL_MANUAL,
        "日本-故转", "新加坡-故转", "韩国-故转", "美国-故转", "其他-故转",
        PROXY_GROUPS.REJECT
    ];

    // 1. 业务分流组
    const serviceGroups = [
        "ChatGPT", "Gemini", "Copilot", "Perplexity", "Claude", "Meta AI",
        "GitHub", "Reddit", "Telegram", "WhatsApp", "Facebook", "YouTube",
        "TikTok", "Netflix", "HBO", "Disney", "Amazon", "Crunchyroll",
        "Spotify", "Nvidia", "Steam", "Games", "Crypto", "Apple", "Google",
        "Microsoft", "Test", "Block", "国外", "国内", "其他"
    ].map(name => ({
        name: name,
        type: "select",
        proxies: baseSelectorProxies
    }));

    // 2. 核心节点组与地区组
    const proxyGroups = [
        ...serviceGroups,
        {
            name: PROXY_GROUPS.ALL_MANUAL,
            type: "select",
            proxies: allProxies
        },
        {
            name: PROXY_GROUPS.ALL_SMART,
            type: smartEnabled ? "smart" : "url-test",
            proxies: allProxies,
            url: "https://cp.cloudflare.com/generate_204",
            interval: 300
        },
        ...createRegionGroups("日本", REGEX.JP),
        ...createRegionGroups("新加坡", REGEX.SG),
        ...createRegionGroups("韩国", REGEX.KR),
        ...createRegionGroups("美国", REGEX.US),
        ...createRegionGroups("其他", { test: (name) => !REGEX.OTHER_EXCLUDE.test(name) })
    ];

    // 3. 全局配置覆盖
    const result = { ...config };
    
    if (fullConfig) {
        Object.assign(result, {
            "port": 7890,
            "socks-port": 7891,
            "mixed-port": 7893,
            "allow-lan": true,
            "mode": "rule",
            "log-level": "info",
            "ipv6": ipv6Enabled,
            "tun": {
                "enable": true,
                "stack": "gvisor",
                "auto-route": true,
                "auto-detect-interface": true
            },
            "profile": { "store-selected": true, "store-fake-ip": true }
        });
    }

    Object.assign(result, {
        "proxy-groups": proxyGroups,
        "rule-providers": ruleProviders,
        "rules": buildRules(),
        "dns": buildDnsConfig(ipv6Enabled)
    });

    return result;
}
