const express = require('express');
const cors = require('cors');

const app = express();
const port = Number(process.env.PORT) || 3000;
const maxTextLength = 10_000;
const allowedLanguages = new Set(['lv', 'en', 'ru']);
const allowedStatuses = new Set(['SARKANS', 'DZELTENS', 'ZAĻŠ']);
const languageNames = { lv: 'latviešu', en: 'angļu', ru: 'krievu' };
const yellowSafety = {
  lv: 'Ziņa var būt reāla, bet drošībai veic pārbaudi oficiālajā mājaslapā vai lietotnē!',
  en: 'This message may be legitimate, but for your safety verify it on the official website or in the app!',
  ru: 'Сообщение может быть настоящим, но для безопасности проверьте его на официальном сайте или в приложении!',
};
const spamSafety = {
  lv: 'Globāls mārketinga vai finanšu spams. Ziņa nav tiešs hakeru uzbrukums, taču esiet uzmanīgi.',
  en: 'Global marketing or financial spam. This is not a direct hacking attack, but remain cautious.',
  ru: 'Глобальный маркетинговый или финансовый спам. Это не прямая хакерская атака, но соблюдайте осторожность.',
};
const statusTemplates = {
  lv: {
    red: 'Kritisks risks! [Uzņēmuma nosaukums] krāpniecība. Nespiediet uz saites un neievadiet datus.',
    yellow: 'Agresīva reklāma vai nepārbaudāma ziņa. Ja tā ir banka, neizmantojiet ziņas saites, bet ieejiet oficiālajā lietotnē.',
    green: 'Ziņa ir droša. Oficiāls paziņojums vai parasts teksts.',
  },
  en: {
    red: 'Critical risk! [Company name] scam. Do not click links or enter data.',
    yellow: 'Aggressive advertising or unverifiable message. If it is from a bank, do not use message links; open the official app instead.',
    green: 'The message is safe. An official notice or ordinary text.',
  },
  ru: {
    red: 'Критический риск! Мошенничество от [название компании]. Не нажимайте на ссылки и не вводите данные.',
    yellow: 'Агрессивная реклама или непроверяемое сообщение. Если это банк, не используйте ссылки из сообщения, а откройте официальное приложение.',
    green: 'Сообщение безопасно. Это официальное уведомление или обычный текст.',
  },
};

app.disable('x-powered-by');
app.use(cors({ origin: process.env.ALLOWED_ORIGIN || true }));
app.use(express.json({ limit: '32kb' }));

app.get('/health', (_request, response) => {
  response.json({ status: 'ok' });
});

async function handleCheckSms(request, response) {
  if (!process.env.OPENAI_API_KEY) {
    console.error('OPENAI_API_KEY is not configured');
    return response.status(500).json({ error: 'Server is not configured' });
  }

  try {
    const text = validateText(request.body?.text);
    const lang = validateLanguage(request.body?.lang);
    const result = await analyzeMessage(text, lang);
    return response.json(result);
  } catch (error) {
    console.error('SMS analysis failed:', error.message);
    const statusCode = error.statusCode || 502;
    return response.status(statusCode).json({
      error: statusCode === 400 ? error.message : 'Unable to analyze message',
    });
  }
}

app.post(['/','/check-sms'], handleCheckSms);

app.use((error, _request, response, next) => {
  if (error?.type === 'entity.parse.failed') {
    return response.status(400).json({ error: 'Request body must be valid JSON' });
  }
  return next(error);
});

app.use((_request, response) => {
  response.status(404).json({ error: 'Not found' });
});

async function analyzeMessage(text, lang) {
  const openAiResponse = await fetch(
    'https://api.openai.com/v1/chat/completions',
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'gpt-4o-mini',
        temperature: 0,
        max_tokens: 220,
        response_format: { type: 'json_object' },
        messages: [
          {
            role: 'system',
            content: [
              'Tu esi PhishArmor Starptautiskais Kiberdrošības Izmeklēšanas Eksperts.',
              'Analizē jebkuras pasaules valsts un valodas SMS, ekrānuzņēmuma OCR tekstu vai tālruņa numuru; nepārvērtē risku tikai valodas, valsts vai uzņēmuma nezināmības dēļ.',
              'Solis A — GLOBĀLĀ SAITES UN DOMĒNA ANATOMIJA: atrodi katru URL. Ja tas izliekas par Amazon, FedEx, DHL, PayPal, Revolut, Netflix, Airbnb, starptautisku banku vai vietēju iestādi, bet domēns nav oficiālais, piešķir SARKANS. Arī negaidīts bit.ly, tinyurl, linktr.ee vai līdzīgs saīsinātājs finanšu ziņā ir SARKANS, ja tas slēpj iespējamu izlikšanos vai datu ievadi.',
              'Solis B — GLOBĀLĀ PSIHOLOĢISKĀ MANIPULĀCIJA: meklē steidzināšanu, konta bloķēšanas draudus, viltus autorizāciju, paroles/kartes datu pieprasījumu, negaidītus paku nodokļus vai laimestus. Jebkurā valodā šādas pazīmes nozīmē SARKANS.',
              `Solis C — STARPTAUTISKAIS SPAMS UN FINANŠU REKLĀMA: agresīvs mārketings, investīciju shēmas, ātra peļņa ar MI, kriptovalūtu “pamācības” vai agresīvi kredīti (piemēram, “0% interest loan up to $5000”) nozīmē DZELTENS, nevis SARKANS. Skaidrojumā dabiski iekļauj: ${spamSafety[lang]}`,
              'NEPOPULĀRA AVOTA PRINCIPS: mazs kurjers vai mazpazīstams starptautisks avots bez spiediena, krāpniecības pazīmēm un viltus saitēm var būt ZAĻŠ vai DZELTENS. Pasaki, ka saturs ir strukturāli drošs vai tikai nepārbaudāms; nebiedē lietotāju bez pamata.',
              `Atbildi tikai ${languageNames[lang]} valodā un tikai tīrā JSON formātā bez Markdown: {"status":"SARKANS|DZELTENS|ZAĻŠ","reason":"..."}.`,
              'reason drīkst būt maksimāli 1–2 īsi, asi un dabiski teikumi; neiekļauj analīzes procesu, URL sarakstus vai liekus paskaidrojumus.',
              `SARKANS 🔴: izmanto īsu, tiešu brīdinājumu pēc šīs struktūras: ${statusTemplates[lang].red}`,
              `DZELTENS 🟡: izmanto īsu brīdinājumu pēc šīs struktūras: ${statusTemplates[lang].yellow} Bankas vai iestādes gadījumā obligāti pievieno: ${yellowSafety[lang]}`,
              `ZAĻŠ 🟢: izmanto īsu apstiprinājumu pēc šīs struktūras: ${statusTemplates[lang].green}`,
              'Ja uzņēmuma nosaukums nav zināms, sarkanajā šablonā [Uzņēmuma nosaukums] aizstāj ar “nezināms avots”.',
            ].join('\n'),
          },
          { role: 'user', content: text },
        ],
      }),
      signal: AbortSignal.timeout(25_000),
    },
  );

  if (!openAiResponse.ok) {
    throw new Error(`Upstream request failed with status ${openAiResponse.status}`);
  }

  const payload = await openAiResponse.json();
  const content = payload?.choices?.[0]?.message?.content;
  if (typeof content !== 'string') {
    throw new Error('Upstream response has an invalid shape');
  }

  return validateResult(JSON.parse(content), lang);
}

function validateText(value) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw badRequest('"text" must be a non-empty string');
  }
  if (value.length > maxTextLength) {
    throw badRequest(`"text" must be at most ${maxTextLength} characters`);
  }
  return value.trim();
}

function validateLanguage(value) {
  if (typeof value !== 'string' || !allowedLanguages.has(value)) {
    throw badRequest('"lang" must be one of: lv, en, ru');
  }
  return value;
}

function validateResult(value, lang) {
  if (
    !value ||
    typeof value !== 'object' ||
    !allowedStatuses.has(value.status) ||
    typeof value.reason !== 'string' ||
    value.reason.trim().length === 0
  ) {
    throw new Error('Upstream response did not match the expected schema');
  }

  const reason = limitReason(value.reason.trim(), value.status, lang);
  return {
    status: value.status,
    reason,
  };
}

function limitReason(reason, status, lang) {
  const cleaned = reason.replace(/```(?:json)?|```/gi, '').replace(/\s+/g, ' ').trim();
  const sentences = cleaned.match(/[^.!?]+[.!?]+|[^.!?]+$/g) || [];
  let shortReason = sentences.slice(0, 2).join(' ').trim();
  if (status === 'DZELTENS' && !shortReason.includes(yellowSafety[lang])) {
    shortReason = `${shortReason} ${yellowSafety[lang]}`.trim();
  }
  return shortReason.slice(0, 360).trim();
}

function badRequest(message) {
  const error = new Error(message);
  error.statusCode = 400;
  return error;
}

app.listen(port, '0.0.0.0', () => {
  console.log(`PhishArmor proxy listening on port ${port}`);
});
