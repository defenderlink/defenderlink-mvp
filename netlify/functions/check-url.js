const fetch = require("node-fetch");
const crypto = require("crypto");
const { RiskEngine, SignalStatus } = require("./risk-engine");

/**
 * CONFIGURATION
 */
const CONFIG = {
  TIMEOUT_MS: 8000,
  RATE_LIMIT_MAX: 20,
  RATE_LIMIT_WINDOW_MS: 60000,
  MAX_AI_RESPONSE_LENGTH: 1000,
  MAX_URL_LENGTH: 2048,
  CACHE_TTL_MS: 300000, // 5 минут
};

/**
 * IN-MEMORY STORAGE
 */
const rateLimiter = new Map();
const resultCache = new Map();

/**
 * MAIN HANDLER
 */
exports.handler = async (event) => {
  // CORS preflight
  if (event.httpMethod === "OPTIONS") {
    return corsResponse(200, "");
  }

  if (event.httpMethod !== "POST") {
    return corsResponse(405, JSON.stringify({ error: "Method Not Allowed" }));
  }

  try {
    // Rate limiting
    const clientIp = event.headers["x-forwarded-for"] || event.headers["x-real-ip"] || "unknown";
    checkRateLimit(clientIp);

    const { url } = JSON.parse(event.body || "{}");

    if (!url) {
      return corsResponse(400, JSON.stringify({ error: "URL не указан" }));
    }

    // Валидация и нормализация URL
    const validatedUrl = validateAndNormalizeUrl(url);
    const domain = extractDomain(validatedUrl);

    // Проверка кэша
    const cacheKey = generateCacheKey(validatedUrl);
    const cached = getCachedResult(cacheKey);
    if (cached) {
      return corsResponse(200, JSON.stringify({ ...cached, cached: true }));
    }

    // Параллельные проверки с таймаутами
    const [googleResult, vtResult, whoisResult] = await Promise.allSettled([
      withTimeout(checkGoogleSafeBrowsing(validatedUrl), CONFIG.TIMEOUT_MS),
      withTimeout(checkVirusTotal(validatedUrl), CONFIG.TIMEOUT_MS),
      withTimeout(checkWhois(domain), CONFIG.TIMEOUT_MS),
    ]);

    const checks = {
      google: getSettledValue(googleResult, { 
        service: "Google Safe Browsing", 
        status: "error",
        details: "Service temporarily unavailable"
      }),
      virustotal: getSettledValue(vtResult, { 
        service: "VirusTotal", 
        status: "error",
        details: "Service temporarily unavailable"
      }),
      whois: getSettledValue(whoisResult, { 
        status: "error",
        details: "WHOIS lookup failed"
      }),
    };

    // ========================================================================
    // RISK ENGINE INTEGRATION
    // ========================================================================

    // Преобразуем результаты API в унифицированные сигналы
    const signals = {
      type: 'url',
      url: validatedUrl,
      domain: domain,
      googleSafeBrowsing: normalizeGoogleResult(checks.google),
      virusTotal: normalizeVTResult(checks.virustotal),
      whois: normalizeWhoisResult(checks.whois),
      metadata: {
        timestamp: new Date().toISOString(),
        clientIp: clientIp,
      },
    };

    // Валидация сигналов
    try {
      RiskEngine.validate(signals);
    } catch (validationError) {
      console.error("Signal validation error:", validationError);
      return corsResponse(500, JSON.stringify({ 
        error: "Internal validation error",
        details: validationError.message
      }));
    }

    // Получаем оценку рисков от RiskEngine
    const riskAssessment = RiskEngine.assess(signals);

    // ========================================================================
    // AI ANALYSIS (conditional)
    // ========================================================================

    let aiExplanation = null;
    const AI_ENABLED = process.env.ENABLE_AI === "true";

    if (AI_ENABLED && RiskEngine.shouldUseAI(riskAssessment)) {
      try {
        aiExplanation = await withTimeout(
          aiExplainRisk(riskAssessment.context),
          10000
        );
      } catch (aiError) {
        console.error("AI explanation error:", aiError);
        // Продолжаем без AI анализа
      }
    }

    // ========================================================================
    // RESPONSE FORMATION
    // ========================================================================

    const response = {
      url: validatedUrl,
      domain: domain,
      
      // Оценка рисков из RiskEngine
      risk: riskAssessment.risk,
      
      // Оригинальные результаты проверок для прозрачности
      checks: {
        google: checks.google,
        virustotal: checks.virustotal,
        whois: checks.whois,
      },
      
      // Детальный анализ из RiskEngine
      analysis: riskAssessment.analysis,
      
      // Резюме и рекомендации из RiskEngine
      summary: riskAssessment.summary,
      recommendations: riskAssessment.recommendations,
      
      // AI объяснение (если доступно)
      ai: aiExplanation
        ? {
            explanation: sanitizeAIResponse(aiExplanation),
            disclaimer: "AI analysis is experimental and should not be the sole basis for decisions",
          }
        : null,
      
      timestamp: new Date().toISOString(),
    };

    // Кэширование результата
    setCachedResult(cacheKey, response);

    return corsResponse(200, JSON.stringify(response));

  } catch (error) {
    console.error("check-url error:", error);

    // Детальная обработка ошибок
    if (error.message.includes("Rate limit")) {
      return corsResponse(429, JSON.stringify({ 
        error: "Слишком много запросов. Попробуйте позже." 
      }));
    }

    if (error.message.includes("Invalid URL") || error.message.includes("not allowed")) {
      return corsResponse(400, JSON.stringify({ error: error.message }));
    }

    return corsResponse(500, JSON.stringify({ 
      error: "Внутренняя ошибка сервера" 
    }));
  }
};

/**
 * SIGNAL NORMALIZATION FUNCTIONS
 */

function normalizeGoogleResult(result) {
  const statusMap = {
    'safe': SignalStatus.SAFE,
    'danger': SignalStatus.DANGER,
    'error': SignalStatus.ERROR,
    'unavailable': SignalStatus.UNAVAILABLE,
  };

  return {
    status: statusMap[result.status] || SignalStatus.ERROR,
    details: result.details || result.service || 'No details available',
  };
}

function normalizeVTResult(result) {
  const statusMap = {
    'safe': SignalStatus.SAFE,
    'suspicious': SignalStatus.SUSPICIOUS,
    'danger': SignalStatus.DANGER,
    'pending': SignalStatus.PENDING,
    'error': SignalStatus.ERROR,
    'unavailable': SignalStatus.UNAVAILABLE,
  };

  return {
    status: statusMap[result.status] || SignalStatus.ERROR,
    score: result.positives || result.score || 0,
    details: result.details || result.service || 'No details available',
  };
}

function normalizeWhoisResult(result) {
  return {
    status: result.status === 'ok' ? 'ok' : (result.status || 'error'),
    domainAgeDays: result.domainAgeDays,
    risk: result.risk,
    details: result.details || 'No WHOIS data available',
  };
}

/**
 * HELPERS
 */

function corsResponse(statusCode, body) {
  return {
    statusCode,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Content-Type": "application/json",
    },
    body,
  };
}

function validateAndNormalizeUrl(url) {
  // Проверка длины
  if (url.length > CONFIG.MAX_URL_LENGTH) {
    throw new Error(`URL слишком длинный (макс. ${CONFIG.MAX_URL_LENGTH} символов)`);
  }

  // Нормализация
  let normalizedUrl = url.trim();
  if (!/^https?:\/\//i.test(normalizedUrl)) {
    normalizedUrl = "https://" + normalizedUrl;
  }

  // Парсинг и валидация
  let parsed;
  try {
    parsed = new URL(normalizedUrl);
  } catch (e) {
    throw new Error("Некорректный формат URL");
  }

  // Проверка протокола
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Разрешены только HTTP и HTTPS протоколы");
  }

  const hostname = parsed.hostname.toLowerCase();

  // Блокировка локальных и внутренних адресов
  const blockedPatterns = [
    /^localhost$/i,
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^169\.254\./,
    /^::1$/,
    /^fc00:/,
    /^fe80:/,
    /^\[::1\]$/,
  ];

  for (const pattern of blockedPatterns) {
    if (pattern.test(hostname)) {
      throw new Error("Внутренние и локальные адреса не разрешены");
    }
  }

  // Проверка на IP адреса
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    const parts = hostname.split(".").map(Number);
    if (parts.some(p => p > 255)) {
      throw new Error("Некорректный IP адрес");
    }
  }

  return normalizedUrl;
}

function extractDomain(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    throw new Error("Не удалось извлечь домен из URL");
  }
}

/**
 * RATE LIMITING
 */

function checkRateLimit(identifier) {
  const now = Date.now();
  const userRequests = rateLimiter.get(identifier) || [];

  const recentRequests = userRequests.filter(
    (time) => now - time < CONFIG.RATE_LIMIT_WINDOW_MS
  );

  if (recentRequests.length >= CONFIG.RATE_LIMIT_MAX) {
    throw new Error("Rate limit exceeded");
  }

  recentRequests.push(now);
  rateLimiter.set(identifier, recentRequests);

  if (Math.random() < 0.01) {
    cleanupRateLimiter();
  }
}

function cleanupRateLimiter() {
  const now = Date.now();
  for (const [key, requests] of rateLimiter.entries()) {
    const recent = requests.filter((time) => now - time < CONFIG.RATE_LIMIT_WINDOW_MS);
    if (recent.length === 0) {
      rateLimiter.delete(key);
    } else {
      rateLimiter.set(key, recent);
    }
  }
}

/**
 * CACHING
 */

function generateCacheKey(url) {
  return crypto.createHash("sha256").update(url).digest("hex");
}

function getCachedResult(key) {
  const cached = resultCache.get(key);
  if (!cached) return null;

  const now = Date.now();
  if (now - cached.timestamp > CONFIG.CACHE_TTL_MS) {
    resultCache.delete(key);
    return null;
  }

  return cached.data;
}

function setCachedResult(key, data) {
  resultCache.set(key, {
    data,
    timestamp: Date.now(),
  });

  if (Math.random() < 0.05) {
    cleanupCache();
  }
}

function cleanupCache() {
  const now = Date.now();
  for (const [key, value] of resultCache.entries()) {
    if (now - value.timestamp > CONFIG.CACHE_TTL_MS) {
      resultCache.delete(key);
    }
  }
}

/**
 * TIMEOUT WRAPPER
 */

async function withTimeout(promise, timeoutMs) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Request timeout")), timeoutMs)
    ),
  ]);
}

/**
 * FETCH WITH TIMEOUT
 */

async function fetchWithTimeout(url, options = {}, timeout = CONFIG.TIMEOUT_MS) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    clearTimeout(timeoutId);
    if (error.name === "AbortError") {
      throw new Error("Request timeout");
    }
    throw error;
  }
}

/**
 * PROMISE SETTLED HELPER
 */

function getSettledValue(result, defaultValue) {
  if (result.status === "fulfilled") {
    return result.value;
  }
  console.error("Promise rejected:", result.reason);
  return defaultValue;
}

/**
 * GOOGLE SAFE BROWSING
 */

async function checkGoogleSafeBrowsing(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!apiKey || apiKey === "your_api_key_here") {
    return { 
      service: "Google Safe Browsing", 
      status: "unavailable", 
      details: "API key not configured" 
    };
  }

  try {
    const res = await fetchWithTimeout(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "defenderlink", clientVersion: "2.0" },
          threatInfo: {
            threatTypes: [
              "MALWARE",
              "SOCIAL_ENGINEERING",
              "UNWANTED_SOFTWARE",
              "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }],
          },
        }),
      }
    );

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    const data = await res.json();

    if (data?.matches?.length > 0) {
      const threatTypes = data.matches.map(m => m.threatType).join(", ");
      return {
        service: "Google Safe Browsing",
        status: "danger",
        details: `Threats detected: ${threatTypes}`,
      };
    }

    return { 
      service: "Google Safe Browsing", 
      status: "safe", 
      details: "No threats detected" 
    };
  } catch (error) {
    console.error("Google Safe Browsing error:", error);
    return {
      service: "Google Safe Browsing",
      status: "error",
      details: "Service temporarily unavailable",
    };
  }
}

/**
 * VIRUSTOTAL
 */

async function checkVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey || apiKey === "your_api_key_here") {
    return { 
      service: "VirusTotal", 
      status: "unavailable", 
      details: "API key not configured" 
    };
  }

  try {
    const urlId = Buffer.from(url).toString("base64").replace(/=/g, "");
    
    const checkRes = await fetchWithTimeout(
      `https://www.virustotal.com/api/v3/urls/${urlId}`,
      { headers: { "x-apikey": apiKey } }
    );

    let stats;
    
    if (checkRes.ok) {
      const checkData = await checkRes.json();
      stats = checkData?.data?.attributes?.last_analysis_stats;
    } else {
      const submitRes = await fetchWithTimeout(
        "https://www.virustotal.com/api/v3/urls",
        {
          method: "POST",
          headers: {
            "x-apikey": apiKey,
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: `url=${encodeURIComponent(url)}`,
        }
      );

      if (!submitRes.ok) {
        throw new Error(`HTTP ${submitRes.status}`);
      }

      return {
        service: "VirusTotal",
        status: "pending",
        details: "Analysis in progress, check again in a minute",
      };
    }

    if (!stats) {
      return { 
        service: "VirusTotal", 
        status: "error", 
        details: "Unable to retrieve analysis" 
      };
    }

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = Object.values(stats).reduce((a, b) => a + b, 0);

    if (malicious > 0) {
      return {
        service: "VirusTotal",
        status: "danger",
        details: `${malicious}/${total} vendors flagged as malicious`,
        score: malicious,
      };
    }

    if (suspicious > 2) {
      return {
        service: "VirusTotal",
        status: "suspicious",
        details: `${suspicious}/${total} vendors flagged as suspicious`,
        score: suspicious,
      };
    }

    return { 
      service: "VirusTotal", 
      status: "safe", 
      details: "No threats detected" 
    };
  } catch (error) {
    console.error("VirusTotal error:", error);
    return {
      service: "VirusTotal",
      status: "error",
      details: "Service temporarily unavailable",
    };
  }
}

/**
 * WHOIS
 */

async function checkWhois(domain) {
  try {
    const res = await fetchWithTimeout(
      `https://api.whois.vu/?q=${encodeURIComponent(domain)}`
    );

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    const data = await res.json();
    const created = data?.created;

    if (!created) {
      return { status: "unknown", details: "Domain age unavailable" };
    }

    const ageDays = Math.floor((Date.now() - new Date(created)) / 86400000);

    let risk = "low";
    let details = `Domain registered ${ageDays} days ago`;

    if (ageDays < 0) {
      return { status: "error", details: "Invalid creation date" };
    } else if (ageDays < 7) {
      risk = "critical";
      details += " (very new - high risk)";
    } else if (ageDays < 30) {
      risk = "high";
      details += " (new - elevated risk)";
    } else if (ageDays < 90) {
      risk = "medium";
      details += " (recent - moderate risk)";
    } else {
      details += " (established)";
    }

    return {
      status: "ok",
      domainAgeDays: ageDays,
      risk,
      details,
    };
  } catch (error) {
    console.error("WHOIS error:", error);
    return {
      status: "error",
      details: "WHOIS lookup failed",
    };
  }
}

/**
 * AI RISK EXPLAINER
 */

async function aiExplainRisk(context) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey || apiKey === "your_api_key_here") {
    return null;
  }

  try {
    const res = await fetchWithTimeout(
      "https://api.openai.com/v1/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "gpt-4o-mini",
          temperature: 0.3,
          max_tokens: 400,
          messages: [
            {
              role: "system",
              content:
                "You are a cybersecurity expert. Provide clear, actionable security analysis. Be concise and use simple language.",
            },
            { role: "user", content: context },
          ],
        }),
      },
      10000
    );

    if (!res.ok) {
      throw new Error(`OpenAI API error: ${res.status}`);
    }

    const data = await res.json();
    return data?.choices?.[0]?.message?.content || null;
  } catch (error) {
    console.error("AI explanation error:", error);
    return null;
  }
}

function sanitizeAIResponse(response) {
  if (!response || typeof response !== "string") return null;

  let sanitized = response.substring(0, CONFIG.MAX_AI_RESPONSE_LENGTH);

  sanitized = sanitized
    .replace(/<script[^>]*>.*?<\/script>/gi, "")
    .replace(/<iframe[^>]*>.*?<\/iframe>/gi, "")
    .replace(/on\w+\s*=/gi, "")
    .replace(/javascript:/gi, "");

  return sanitized.trim();
}