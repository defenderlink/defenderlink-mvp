const fetch = require("node-fetch");

const GOOGLE_API_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;
const VT_KEY = process.env.VIRUSTOTAL_API_KEY;

// Проверка Google Safe Browsing
async function checkGoogleSafeBrowsing(url) {
  if (!GOOGLE_API_KEY) {
    return { service: "Google Safe Browsing", status: "warning", details: "API ключ не установлен" };
  }

  const body = {
    client: { clientId: "defenderlink", clientVersion: "1.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }],
    },
  };

  try {
    const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`, {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "Content-Type": "application/json" },
    });

    if (!res.ok) return { service: "Google Safe Browsing", status: "error", details: `Ошибка ${res.status}` };
    const data = await res.json();
    return { service: "Google Safe Browsing", status: data.matches ? "unsafe" : "safe", details: data.matches || [] };
  } catch (e) {
    return { service: "Google Safe Browsing", status: "error", details: e.message };
  }
}

// Проверка VirusTotal
async function checkVirusTotalUrl(url) {
  if (!VT_KEY) {
    return { service: "VirusTotal", status: "warning", details: "API ключ не установлен" };
  }

  try {
    const res = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: { "x-apikey": VT_KEY, "Content-Type": "application/x-www-form-urlencoded" },
      body: `url=${encodeURIComponent(url)}`,
    });

    if (!res.ok) return { service: "VirusTotal", status: "error", details: `Ошибка ${res.status}` };

    const data = await res.json();
    const id = data.data.id;

    const reportRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, {
      headers: { "x-apikey": VT_KEY },
    });
    const report = await reportRes.json();

    const stats = report.data?.attributes?.stats || {};
    const malicious = stats.malicious || 0;

    return {
      service: "VirusTotal",
      status: malicious > 0 ? "unsafe" : "safe",
      details: stats,
    };
  } catch (e) {
    return { service: "VirusTotal", status: "error", details: e.message };
  }
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  try {
    const { url } = JSON.parse(event.body);
    if (!url) {
      return { statusCode: 400, body: JSON.stringify({ error: "URL обязателен" }) };
    }

    const [gsb, vt] = await Promise.all([
      checkGoogleSafeBrowsing(url),
      checkVirusTotalUrl(url),
    ]);

    return {
      statusCode: 200,
      headers: { "Access-Control-Allow-Origin": "*" },
      body: JSON.stringify({ results: [gsb, vt] }),
    };
  } catch (error) {
    return { statusCode: 500, body: JSON.stringify({ error: error.message }) };
  }
};
