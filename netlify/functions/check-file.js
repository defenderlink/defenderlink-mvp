const Busboy = require('busboy');
const fetch = require('node-fetch');
const FormData = require('form-data');

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
    const fileBuffer = await parseFile(event);
    if (!fileBuffer) {
      return {
        statusCode: 400,
        headers: { 'Access-Control-Allow-Origin': '*' },
        body: JSON.stringify({ error: 'Файл не загружен' }),
      };
    }

    const vt = await scanWithVirusTotal(fileBuffer);

    return {
      statusCode: 200,
      headers: { 'Access-Control-Allow-Origin': '*' },
      body: JSON.stringify(vt),
    };
  } catch (error) {
    console.error('check-file error:', error);
    return {
      statusCode: 500,
      headers: { 'Access-Control-Allow-Origin': '*' },
      body: JSON.stringify({ error: error.message }),
    };
  }
};

function parseFile(event) {
  return new Promise((resolve, reject) => {
    try {
      const headers = event.headers || {};
      const contentType = headers['content-type'] || headers['Content-Type'];
      if (!contentType) return resolve(null);

      const busboy = new Busboy({ headers: { 'content-type': contentType } });
      let chunks = [];

      busboy.on('file', (_, file) => {
        file.on('data', (data) => chunks.push(data));
      });

      busboy.on('finish', () => {
        const buffer = Buffer.concat(chunks);
        resolve(buffer.length ? buffer : null);
      });

      busboy.on('error', (err) => reject(err));

      const body = Buffer.from(event.body || '', event.isBase64Encoded ? 'base64' : 'utf8');
      busboy.end(body);
    } catch (e) {
      reject(e);
    }
  });
}

async function scanWithVirusTotal(fileBuffer) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return { service: 'VirusTotal', status: 'error', details: 'API ключ не установлен' };
  }

  // Загрузка файла
  const form = new FormData();
  form.append('file', fileBuffer, { filename: 'upload.bin' });

  const uploadRes = await fetch('https://www.virustotal.com/vtapi/v2/file/scan', {
    method: 'POST',
    headers: { apikey: apiKey },
    body: form,
  });

  if (!uploadRes.ok) {
    return { service: 'VirusTotal', status: 'error', details: `Ошибка загрузки: ${uploadRes.status}` };
  }

  const uploadData = await uploadRes.json();
  const resource = uploadData.resource || uploadData.sha256 || uploadData.sha1;
  const permalink = uploadData.permalink || '';

  // Polling отчёта
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  let reportData = null;
  for (let i = 0; i < 6; i++) { // ждём до ~20 секунд
    await sleep(i === 0 ? 5000 : 3000);
    const reportRes = await fetch(`https://www.virustotal.com/vtapi/v2/file/report?apikey=${apiKey}&resource=${encodeURIComponent(resource)}`);
    if (!reportRes.ok) continue;
    const data = await reportRes.json();
    if (data && data.response_code === 1) { 
      reportData = data; 
      break; 
    }
  }

  if (!reportData) {
    return {
      service: 'VirusTotal',
      status: 'pending',
      details: `Анализ ещё в процессе. Проверьте позже: ${permalink}`,
    };
  }

  const positives = reportData.positives || 0;
  const total = reportData.total || 0;

  if (positives === 0) {
    return {
      service: 'VirusTotal',
      status: 'safe',
      details: 'Файл безопасен (угроз не обнаружено)',
    };
  } else if (positives < total * 0.2) {
    return {
      service: 'VirusTotal',
      status: 'suspicious',
      details: `Файл подозрительный: ${positives} из ${total} антивирусов нашли угрозы`,
    };
  } else {
    return {
      service: 'VirusTotal',
      status: 'danger',
      details: `Файл опасен: ${positives} из ${total} антивирусов нашли угрозы`,
    };
  }
}