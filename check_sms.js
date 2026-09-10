const express = require('express');
const cors = require('cors');

const app = express();
const port = Number(process.env.PORT) || 3000;
const maxTextLength = 10_000;
const allowedLanguages = new Set(['lv', 'en', 'ru']);
const allowedStatuses = new Set(['SARKANS', 'DZELTENS', 'ZAĻŠ']);
const languageNames = { lv: 'latviešu', en: 'angļu', ru: 'krievu' };

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
        max_tokens: 300,
        response_format: { type: 'json_object' },
        messages: [
          {
            role: 'system',
            content: [
              'Tu esi PhishArmor kiberdrošības analītiķis.',
              'Analizē SMS saturu tikai krāpniecības riska ziņā.',
              'Atgriez tikai derīgu JSON objektu bez Markdown vai papildu teksta.',
              'Shēma: {"status":"SARKANS|DZELTENS|ZAĻŠ","reason":"string"}.',
              `Skaidrojumu raksti ${languageNames[lang]} valodā.`,
              'SARKANS nozīmē skaidras krāpniecības pazīmes vai steidzamu finanšu risku.',
              'DZELTENS nozīmē aizdomīgus signālus, bet nepietiekamu pamatojumu sarkanam statusam.',
              'ZAĻŠ nozīmē, ka būtiskas krāpniecības pazīmes nav atrastas.',
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

  return validateResult(JSON.parse(content));
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

function validateResult(value) {
  if (
    !value ||
    typeof value !== 'object' ||
    !allowedStatuses.has(value.status) ||
    typeof value.reason !== 'string' ||
    value.reason.trim().length === 0
  ) {
    throw new Error('Upstream response did not match the expected schema');
  }

  return { status: value.status, reason: value.reason.trim() };
}

function badRequest(message) {
  const error = new Error(message);
  error.statusCode = 400;
  return error;
}

app.listen(port, '0.0.0.0', () => {
  console.log(`PhishArmor proxy listening on port ${port}`);
});
