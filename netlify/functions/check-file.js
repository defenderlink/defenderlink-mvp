const fetch = require("node-fetch");

const VT_KEY = process.env.VIRUSTOTAL_API_KEY;

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }
  if (!VT_KEY) {
    return { statusCode: 500, body: JSON.stringify({ error: "VIRUSTOTAL_API_KEY не установлен" }) };
  }

  try {
    const body = JSON.parse(event.body);
    const fileContent = body.file; // base64
    const buffer = Buffer.from(fileContent, "base64");

    // Загружаем файл
    const uploadRes = await fetch("https://www.virustotal.com/api/v3/files", {
      method: "POST",
      headers: { "x-apikey": VT_KEY },
      body: buffer,
    });

    const uploadData = await uploadRes.json();
    if (!uploadRes.ok) {
      return { statusCode: uploadRes.status, body: JSON.stringify(uploadData) };
    }

    const analysisId = uploadData.data.id;

    // Ждем анализа
    let report = null;
    for (let i = 0; i < 5; i++) {
      const reportRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { "x-apikey": VT_KEY },
      });
      const data = await reportRes.json();
      if (data.data?.attributes?.status === "completed") {
        report = data;
        break;
      }
      await new Promise((res) => setTimeout(res, 3000));
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ result: report || { status: "pending" } }),
    };
  } catch (e) {
    return { statusCode: 500, body: JSON.stringify({ error: e.message }) };
  }
};
