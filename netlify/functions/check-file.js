const Busboy = require("busboy");
const fetch = require("node-fetch");
const FormData = require("form-data");
const crypto = require("crypto");
const { RiskEngine, SignalStatus } = require("./risk-engine");

/**
 * CONFIGURATION
 */
const CONFIG = {
  MAX_FILE_SIZE: 100 * 1024 * 1024, // 100 MB
  TIMEOUT_MS: 30000,
  VT_POLL_ATTEMPTS: 8,
  VT_POLL_INITIAL_DELAY: 5000,
  VT_POLL_RETRY_DELAY: 4000,
  RATE_LIMIT_MAX: 10,
  RATE_LIMIT_WINDOW_MS: 60000,
  MAX_AI_RESPONSE_LENGTH: 1000,
  CACHE_TTL_MS: 600000, // 10 минут
  DANGEROUS_EXTENSIONS: [
    ".exe", ".dll", ".bat", ".cmd", ".com", ".scr", ".pif",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1",
    ".msi", ".jar", ".app", ".deb", ".rpm", ".sh", ".cpl"
  ],
  SUSPICIOUS_MIMETYPES: [
    "application/x-msdownload",
    "application/x-executable",
    "application/x-dosexec",
    "application/x-msdos-program",
    "application/x-bat",
    "application/x-sh",
  ],
};

/**
 * IN-MEMORY STORAGE
 */
const rateLimiter = new Map();
const resultCache = new Map();
const scanQueue = new Map();

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

    // Парсинг файла с валидацией
    const file = await parseFile(event);

    if (!file || !file.buffer) {
      return corsResponse(400, JSON.stringify({ error: "Файл не загружен" }));
    }

    // Валидация файла
    validateFile(file);

    // Проверка кэша по хешу файла
    const fileHash = calculateFileHash(file.buffer);
    const cacheKey = `file:${fileHash}`;
    const cached = getCachedResult(cacheKey);
    
    if (cached) {
      return corsResponse(200, JSON.stringify({ ...cached, cached: true, fileHash }));
    }

    // Дедупликация одновременных сканирований
    if (scanQueue.has(fileHash)) {
      return corsResponse(202, JSON.stringify({
        message: "Файл уже сканируется, повторите запрос через несколько секунд",
        fileHash,
        status: "processing"
      }));
    }

    scanQueue.set(fileHash, true);

    try {
      // Статический анализ
      const staticAnalysis = performStaticAnalysis(file);

      // VirusTotal сканирование
      const vtResult = await withTimeout(
        scanWithVirusTotal(file, fileHash),
        CONFIG.TIMEOUT_MS
      );

      // ====================================================================
      // RISK ENGINE INTEGRATION
      // ====================================================================

      // Преобразуем результаты в унифицированные сигналы
      const signals = {
        type: 'file',
        filename: file.filename,
        fileSize: file.buffer.length,
        mimeType: file.mimeType,
        fileHash: fileHash,
        virusTotal: normalizeVTResult(vtResult),
        staticAnalysis: normalizeStaticAnalysis(staticAnalysis),
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

      // ====================================================================
      // AI ANALYSIS (conditional)
      // ====================================================================

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

      // ====================================================================
      // RESPONSE FORMATION
      // ====================================================================

      const response = {
        file: {
          filename: sanitizeFilename(file.filename),
          size: file.buffer.length,
          mimeType: file.mimeType,
          hash: {
            sha256: fileHash,
          },
        },
        
        // Оценка рисков из RiskEngine
        risk: riskAssessment.risk,
        
        // Оригинальные результаты проверок
        checks: {
          virustotal: vtResult,
          static: staticAnalysis,
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

    } finally {
      scanQueue.delete(fileHash);
    }

  } catch (error) {
    console.error("check-file error:", error);

    if (error.message.includes("Rate limit")) {
      return corsResponse(429, JSON.stringify({ 
        error: "Слишком много запросов. Попробуйте позже." 
      }));
    }

    if (error.message.includes("File too large")) {
      return corsResponse(413, JSON.stringify({ 
        error: `Файл слишком большой. Максимум ${CONFIG.MAX_FILE_SIZE / 1024 / 1024} MB` 
      }));
    }

    if (error.message.includes("Invalid file") || error.message.includes("Dangerous")) {
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

function normalizeVTResult(result) {
  const statusMap = {
    'safe': SignalStatus.SAFE,
    'low-risk': SignalStatus.LOW_RISK,
    'suspicious': SignalStatus.SUSPICIOUS,
    'danger': SignalStatus.DANGER,
    'pending': SignalStatus.PENDING,
    'error': SignalStatus.ERROR,
    'unavailable': SignalStatus.UNAVAILABLE,
  };

  return {
    status: statusMap[result.status] || SignalStatus.ERROR,
    positives: result.positives || 0,
    total: result.total || 0,
    percentage: result.percentage || 0,
    details: result.details || result.service || 'No details available',
  };
}

function normalizeStaticAnalysis(analysis) {
  return {
    fileExtension: analysis.fileExtension || '',
    hasExecutableExtension: analysis.hasExecutableExtension || false,
    hasSuspiciousMimeType: analysis.hasSuspiciousMimeType || false,
    extensionMismatch: analysis.extensionMismatch || false,
    entropy: analysis.entropy || 0,
    highEntropy: analysis.highEntropy || false,
    fileSignature: analysis.fileSignature || 'Unknown',
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

function sanitizeFilename(filename) {
  return filename
    .replace(/[<>:"|?*]/g, "")
    .replace(/\.\./g, "")
    .substring(0, 255);
}

/**
 * FILE VALIDATION
 */

function validateFile(file) {
  if (file.buffer.length > CONFIG.MAX_FILE_SIZE) {
    throw new Error(`File too large: ${file.buffer.length} bytes`);
  }

  if (file.buffer.length === 0) {
    throw new Error("Invalid file: empty file");
  }

  const ext = getFileExtension(file.filename);
  if (CONFIG.DANGEROUS_EXTENSIONS.includes(ext.toLowerCase())) {
    file.isDangerousExtension = true;
  }

  if (CONFIG.SUSPICIOUS_MIMETYPES.includes(file.mimeType)) {
    file.isSuspiciousMimeType = true;
  }

  return true;
}

function getFileExtension(filename) {
  const match = filename.match(/\.([^.]+)$/);
  return match ? `.${match[1]}` : "";
}

/**
 * STATIC ANALYSIS
 */

function performStaticAnalysis(file) {
  const analysis = {
    fileExtension: getFileExtension(file.filename),
    hasExecutableExtension: file.isDangerousExtension || false,
    hasSuspiciousMimeType: file.isSuspiciousMimeType || false,
    entropy: calculateEntropy(file.buffer),
    hasNullBytes: file.buffer.includes(0x00),
    fileSignature: detectFileSignature(file.buffer),
  };

  analysis.extensionMismatch = checkExtensionMismatch(
    analysis.fileExtension,
    analysis.fileSignature
  );

  analysis.highEntropy = analysis.entropy > 7.5;

  analysis.isSuspicious =
    analysis.hasExecutableExtension ||
    analysis.hasSuspiciousMimeType ||
    analysis.extensionMismatch ||
    analysis.highEntropy;

  return analysis;
}

function calculateEntropy(buffer) {
  const freq = new Array(256).fill(0);
  for (let i = 0; i < buffer.length; i++) {
    freq[buffer[i]]++;
  }

  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      const p = freq[i] / buffer.length;
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

function detectFileSignature(buffer) {
  const signatures = {
    "504B0304": "ZIP/JAR/APK",
    "4D5A": "EXE/DLL",
    "7F454C46": "ELF",
    "CAFEBABE": "Java Class",
    "89504E47": "PNG",
    "FFD8FF": "JPEG",
    "25504446": "PDF",
    "504B0708": "ZIP",
    "D0CF11E0": "MS Office",
  };

  const header = buffer.slice(0, 8).toString("hex").toUpperCase();

  for (const [sig, type] of Object.entries(signatures)) {
    if (header.startsWith(sig)) {
      return type;
    }
  }

  return "Unknown";
}

function checkExtensionMismatch(extension, signature) {
  const mapping = {
    ".exe": ["EXE/DLL"],
    ".dll": ["EXE/DLL"],
    ".zip": ["ZIP/JAR/APK", "ZIP"],
    ".jar": ["ZIP/JAR/APK"],
    ".apk": ["ZIP/JAR/APK"],
    ".png": ["PNG"],
    ".jpg": ["JPEG"],
    ".jpeg": ["JPEG"],
    ".pdf": ["PDF"],
    ".doc": ["MS Office"],
    ".docx": ["ZIP/JAR/APK"],
    ".xls": ["MS Office"],
    ".xlsx": ["ZIP/JAR/APK"],
  };

  const expected = mapping[extension.toLowerCase()];
  if (!expected) return false;

  return !expected.includes(signature);
}

/**
 * FILE PARSER
 */

function parseFile(event) {
  return new Promise((resolve, reject) => {
    try {
      const headers = event.headers || {};
      const contentType = headers["content-type"] || headers["Content-Type"];

      if (!contentType) {
        return resolve(null);
      }

      const busboy = new Busboy({
        headers: { "content-type": contentType },
        limits: {
          fileSize: CONFIG.MAX_FILE_SIZE,
          files: 1,
        },
      });

      const chunks = [];
      let filename = "upload.bin";
      let mimeType = "application/octet-stream";
      let fileSizeExceeded = false;

      busboy.on("file", (_, file, info) => {
        filename = info?.filename || filename;
        mimeType = info?.mimeType || mimeType;

        file.on("data", (data) => {
          chunks.push(data);
        });

        file.on("limit", () => {
          fileSizeExceeded = true;
          file.resume();
        });
      });

      busboy.on("finish", () => {
        if (fileSizeExceeded) {
          return reject(new Error("File too large"));
        }

        const buffer = Buffer.concat(chunks);
        if (!buffer.length) return resolve(null);
        resolve({ buffer, filename, mimeType });
      });

      busboy.on("error", (error) => {
        reject(new Error(`File parsing error: ${error.message}`));
      });

      const body = Buffer.from(
        event.body || "",
        event.isBase64Encoded ? "base64" : "utf8"
      );
      busboy.end(body);

      setTimeout(() => {
        reject(new Error("File parsing timeout"));
      }, 15000);
    } catch (e) {
      reject(e);
    }
  });
}

/**
 * FILE HASHING
 */

function calculateFileHash(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

/**
 * VIRUSTOTAL SCAN
 */

async function scanWithVirusTotal(file, fileHash) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey || apiKey === "your_api_key_here") {
    return {
      service: "VirusTotal",
      status: "unavailable",
      details: "API key not configured",
    };
  }

  try {
    // Проверка по хешу
    const existingReport = await checkVirusTotalByHash(apiKey, fileHash);
    if (existingReport) {
      return existingReport;
    }

    // Загрузка нового файла
    const form = new FormData();
    form.append("file", file.buffer, { filename: file.filename });

    const uploadRes = await fetchWithTimeout(
      "https://www.virustotal.com/vtapi/v2/file/scan",
      {
        method: "POST",
        headers: { apikey: apiKey },
        body: form,
      },
      CONFIG.TIMEOUT_MS
    );

    if (!uploadRes.ok) {
      throw new Error(`VirusTotal upload failed: ${uploadRes.status}`);
    }

    const uploadData = await uploadRes.json();
    const resource = uploadData.resource || uploadData.sha256 || uploadData.sha1;

    if (!resource) {
      return {
        service: "VirusTotal",
        status: "error",
        details: "Failed to upload file",
      };
    }

    // Ожидание результатов
    const report = await pollVirusTotalReport(apiKey, resource);

    if (!report) {
      return {
        service: "VirusTotal",
        status: "pending",
        details: "Analysis in progress, check again later",
      };
    }

    return parseVirusTotalReport(report);
  } catch (error) {
    console.error("VirusTotal error:", error);
    return {
      service: "VirusTotal",
      status: "error",
      details: error.message || "Service temporarily unavailable",
    };
  }
}

async function checkVirusTotalByHash(apiKey, hash) {
  try {
    const res = await fetchWithTimeout(
      `https://www.virustotal.com/vtapi/v2/file/report?apikey=${apiKey}&resource=${hash}`,
      {},
      5000
    );

    if (!res.ok) return null;

    const data = await res.json();
    if (data.response_code === 1) {
      return parseVirusTotalReport(data);
    }

    return null;
  } catch (error) {
    console.error("Hash check error:", error);
    return null;
  }
}

function parseVirusTotalReport(report) {
  const positives = report.positives || 0;
  const total = report.total || 0;

  if (total === 0) {
    return {
      service: "VirusTotal",
      status: "error",
      details: "No scan results available",
    };
  }

  const percentage = (positives / total) * 100;

  if (positives === 0) {
    return {
      service: "VirusTotal",
      status: "safe",
      positives,
      total,
      percentage: 0,
      details: "No threats detected",
    };
  }

  if (percentage < 10) {
    return {
      service: "VirusTotal",
      status: "low-risk",
      positives,
      total,
      percentage: Math.round(percentage),
      details: `Low detection rate: ${positives}/${total} vendors`,
    };
  }

  if (percentage < 30) {
    return {
      service: "VirusTotal",
      status: "suspicious",
      positives,
      total,
      percentage: Math.round(percentage),
      details: `Moderate detection rate: ${positives}/${total} vendors`,
    };
  }

  return {
    service: "VirusTotal",
    status: "danger",
    positives,
    total,
    percentage: Math.round(percentage),
    details: `High detection rate: ${positives}/${total} vendors flagged as malicious`,
  };
}

async function pollVirusTotalReport(apiKey, resource) {
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  await sleep(CONFIG.VT_POLL_INITIAL_DELAY);

  for (let i = 0; i < CONFIG.VT_POLL_ATTEMPTS; i++) {
    try {
      const res = await fetchWithTimeout(
        `https://www.virustotal.com/vtapi/v2/file/report?apikey=${apiKey}&resource=${encodeURIComponent(
          resource
        )}`,
        {},
        5000
      );

      if (!res.ok) {
        console.warn(`VT poll attempt ${i + 1} failed: ${res.status}`);
        await sleep(CONFIG.VT_POLL_RETRY_DELAY);
        continue;
      }

      const data = await res.json();

      if (data.response_code === 1) {
        return data;
      }

      if (data.response_code === -2) {
        await sleep(CONFIG.VT_POLL_RETRY_DELAY);
        continue;
      }

      console.warn(`VT response code: ${data.response_code}`);
      await sleep(CONFIG.VT_POLL_RETRY_DELAY);
    } catch (error) {
      console.error(`VT poll error attempt ${i + 1}:`, error);
      await sleep(CONFIG.VT_POLL_RETRY_DELAY);
    }
  }

  return null;
}

/**
 * TIMEOUT & FETCH HELPERS
 */

async function withTimeout(promise, timeoutMs) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Request timeout")), timeoutMs)
    ),
  ]);
}

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
          temperature: 0.2,
          max_tokens: 400,
          messages: [
            {
              role: "system",
              content:
                "You are a malware analyst. Provide clear, actionable security analysis. Be concise and use understandable language.",
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