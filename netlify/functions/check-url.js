const fetch = require('node-fetch');

exports.handler = async (event) => {
  // CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
      },
      body: '',
    };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  try {
    const { url } = JSON.parse(event.body || '{}');
    if (!url) {
      return {
        statusCode: 400,
        headers: { 'Access-Control-Allow-Origin': '*' },
        body: JSON.stringify({ error: 'URL не указан' }),
      };
    }

    const results = [];
    results.push(await checkGoogleSafeBrowsing(url));
    results.push(await checkVirusTotal(url));

    return {
      statusCode: 200,
      headers: { 'Access-Control-Allow-Origin': '*' },
      body: JSON.stringify({ url, results }),
    };
  } catch (error) {
    console.error('check-url error:', error);
    return {
      statusCode: 500,
      headers: { 'Access-Control-Allow-Origin': '*' },
      body: JSON.stringify({ error: error.message }),
    };
  }
};

async function checkGoogleSafeBrowsing(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!apiKey) {
    return { service: 'Google Safe Browsing', status: 'error', details: 'API ключ не установлен' };
  }

  try {
    const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: "defenderlink", clientVersion: "1.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      }),
    });

    if (!res.ok) {
      return { service: 'Google Safe Browsing', status: 'error', details: `Ошибка ${res.status}` };
    }

    const data = await res.json();
    if (data && data.matches && data.matches.length > 0) {
      return {
        service: 'Google Safe Browsing',
        status: 'danger',
        details: 'Сайт небезопасен (обнаружены угрозы)',
      };
    }

    return { service: 'Google Safe Browsing', status: 'safe', details: 'Сайт безопасен' };
  } catch (e) {
    return { service: 'Google Safe Browsing', status: 'error', details: e.message };
  }
}

async function checkVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return { service: 'VirusTotal', status: 'error', details: 'API ключ не установлен' };
  }

  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/urls`, {
      method: 'POST',
      headers: { 'x-apikey': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `url=${encodeURIComponent(url)}`,
    });

    if (!res.ok) {
      return { service: 'VirusTotal', status: 'error', details: `Ошибка загрузки: ${res.status}` };
    }

    const data = await res.json();
    const id = data.data?.id;

    if (!id) {
      return { service: 'VirusTotal', status: 'error', details: 'Не удалось получить ID анализа' };
    }

    // Получение отчета
    const reportRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${id}`, {
      headers: { 'x-apikey': apiKey },
    });

    if (!reportRes.ok) {
      return { service: 'VirusTotal', status: 'error', details: `Ошибка получения отчета: ${reportRes.status}` };
    }

    const reportData = await reportRes.json();
    const stats = reportData.data?.attributes?.stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;

    if (malicious > 0) {
      return { service: 'VirusTotal', status: 'danger', details: `Небезопасный сайт (${malicious} антивирусов обнаружили угрозы)` };
    } else if (suspicious > 0) {
      return { service: 'VirusTotal', status: 'suspicious', details: `Подозрительный сайт (${suspicious} сработок)` };
    } else {
      return { service: 'VirusTotal', status: 'safe', details: `Сайт безопасен (${harmless} проверок без угроз)` };
    }
  } catch (e) {
    return { service: 'VirusTotal', status: 'error', details: e.message };
  }
}