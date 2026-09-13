const crypto = require('node:crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
const port = Number(process.env.PORT) || 3000;
const upstreamTimeoutMs = 25_000;
const maxTextLength = 10_000;
const maxImageBytes = 2 * 1024 * 1024;
const maxImageBase64Length = Math.ceil(maxImageBytes / 3) * 4 + 16;
const manualLimit = 5;
const manualWindowMs = 60 * 60 * 1000;
const premiumLimit = 30;
const premiumWindowMs = 24 * 60 * 60 * 1000;
const allowedLanguages = new Set(['lv', 'en', 'ru']);
const allowedInputTypes = new Set(['message', 'phone_number', 'call_transcript']);
const allowedImageTypes = new Set(['image/jpeg', 'image/png', 'image/webp']);
const verifiedDomains = new Set([
  'primero.lv', 'go.primero.lv', 'swedbank.lv', 'omniva.lv', 'dpd.lv', 'latvija.gov.lv',
]);
const allowedOrigins = new Set(
  (process.env.ALLOWED_ORIGINS || '').split(',').map((origin) => origin.trim()).filter(Boolean),
);
const clientApiKey = process.env.PHISHARMOR_API_KEY?.trim() || '';
const mobileClientName = 'phisharmor-android';
const languageNames = { lv: 'latviešu', en: 'angļu', ru: 'krievu' };
const limitMessages = {
  lv: 'Pārsniegts pieprasījumu limits. Lūdzu, mēģiniet vēlreiz vēlāk, lai aizsargātu sistēmas resursus.',
  en: 'The request limit was exceeded. Please try again later to protect system resources.',
  ru: 'Лимит запросов превышен. Повторите попытку позже для защиты системных ресурсов.',
};
const errorMessages = {
  lv: 'Drošības pārbaudi neizdevās pabeigt. Lūdzu, mēģiniet vēlreiz un neklikšķiniet uz saitēm, kamēr ziņa nav pārbaudīta.',
  en: 'The security check could not be completed. Please try again and do not click links until the message is checked.',
  ru: 'Не удалось завершить проверку безопасности. Повторите попытку и не нажимайте на ссылки, пока сообщение не проверено.',
};

const analysisSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    scam_indicators_found: {
      type: 'array', items: { type: 'string', minLength: 1, maxLength: 240 }, maxItems: 12,
    },
    technical_analysis: { type: 'string', minLength: 1, maxLength: 600 },
    risk_score: { type: 'number', minimum: 0, maximum: 1 },
    is_phishing: { type: 'boolean' },
    action_required: { type: 'string', enum: ['BLOCK_AND_ALERT', 'MONITOR', 'ALLOW'] },
    user_alert_message_lv: { type: 'string', minLength: 1, maxLength: 360 },
  },
  required: [
    'scam_indicators_found', 'technical_analysis', 'risk_score', 'is_phishing',
    'action_required', 'user_alert_message_lv',
  ],
};

const regionalSearchProfiles = [
  { prefixes: ['371'], region: 'Latvia', terms: ['scam', 'kas zvanīja', 'krāpnieki'] },
  { prefixes: ['370'], region: 'Lithuania', terms: ['scam', 'kas skambino', 'sukčiai'] },
  { prefixes: ['372'], region: 'Estonia', terms: ['scam', 'kes helistas', 'pettus'] },
  { prefixes: ['44'], region: 'United Kingdom', terms: ['who called me', 'scam lookup', 'fraud report'] },
  { prefixes: ['1'], region: 'United States or Canada', terms: ['scam report', 'who called', 'spam call'] },
  { prefixes: ['33'], region: 'France', terms: ['numéro arnaque', "qui m'a appelé", 'appel spam'] },
  { prefixes: ['49'], region: 'Germany', terms: ['Betrugsnummer', 'wer hat angerufen', 'Spam Anruf'] },
  { prefixes: ['34'], region: 'Spain', terms: ['número estafa', 'quién me llamó', 'llamada spam'] },
  { prefixes: ['39'], region: 'Italy', terms: ['numero truffa', 'chi mi ha chiamato', 'chiamata spam'] },
  { prefixes: ['81'], region: 'Japan', terms: ['迷惑電話', '詐欺電話', '誰からの電話'] },
  { prefixes: ['86'], region: 'China', terms: ['诈骗电话', '骚扰电话', '谁打来的'] },
  { prefixes: ['91'], region: 'India', terms: ['scam number', 'who called', 'spam call'] },
  { prefixes: ['7'], region: 'Russia or Kazakhstan', terms: ['номер мошенники', 'кто звонил', 'спам звонок'] },
];

const requestBuckets = new Map();

app.disable('x-powered-by');
app.use(helmet());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.has(origin)) return callback(null, true);
    return callback(new Error('CORS origin denied'));
  },
  allowedHeaders: ['Content-Type', 'X-PhishArmor-Key', 'X-PhishArmor-App', 'X-PhishArmor-Mode'],
  methods: ['GET', 'POST', 'OPTIONS'],
}));
app.use(express.json({ limit: '4mb' }));

if (!clientApiKey && allowedOrigins.size === 0) {
  console.error('No ALLOWED_ORIGINS or PHISHARMOR_API_KEY configured; all analysis requests will be denied.');
}

app.get('/health', (_request, response) => response.json({ status: 'ok' }));

app.post(['/','/check-sms'], async (request, response, next) => {
  try {
    if (!isAuthorizedRequest(request)) {
      return response.status(403).json(neutralResult('en', 'Request not authorized'));
    }

    const language = requestLanguage(request);
    const premiumBackground = isPremiumBackgroundRequest(request);
    if (!consumeRateLimit(request.ip, premiumBackground)) {
      return response.status(429).json(rateLimitResult(language));
    }

    const image = validateImage(
      request.body?.image_base64 ?? request.body?.image_data,
      request.body?.image_mime_type,
    );
    const rawText = request.body?.text ?? request.body?.input_text;
    const text = rawText == null || rawText === ''
      ? 'No extracted text. Analyze the attached image.'
      : validateText(rawText);
    const inputType = validateInputType(request.body?.input_type);

    const localResult = classifyVerifiedDomain(text, language);
    if (localResult) return response.json(localResult);
    if (!process.env.OPENAI_API_KEY) throw new Error('OPENAI_API_KEY is not configured');
    return response.json(await analyzeMessage(text, language, inputType, image));
  } catch (error) {
    return next(error);
  }
});

app.use((_request, response) => response.status(404).json(neutralResult('en', 'Endpoint not found')));

app.use((error, request, response, _next) => {
  const statusCode = error?.type === 'entity.too.large' || error?.type === 'entity.parse.failed'
    ? 400
    : Number.isInteger(error?.statusCode) ? error.statusCode : 502;
  const language = requestLanguage(request);
  const publicMessage = statusCode === 400
    ? 'Request body must be valid JSON and contain an image no larger than 2 MB.'
    : errorMessages[language];
  console.error('Request failed:', error?.message || 'Unknown server error');
  response.status(statusCode).json(neutralResult(language, publicMessage));
});

function requestLanguage(request) {
  const value = request.body?.language ?? request.body?.lang;
  return allowedLanguages.has(value) ? value : 'en';
}

function isAuthorizedRequest(request) {
  const providedKey = request.get('X-PhishArmor-Key') || '';
  if (clientApiKey && providedKey) {
    const expected = Buffer.from(clientApiKey);
    const actual = Buffer.from(providedKey);
    if (expected.length === actual.length && crypto.timingSafeEqual(expected, actual)) return true;
  }
  if (!clientApiKey && request.get('X-PhishArmor-App') === mobileClientName) return true;
  return Boolean(request.get('Origin') && allowedOrigins.has(request.get('Origin')));
}

function isPremiumBackgroundRequest(request) {
  return request.body?.is_background === true || request.body?.background === true ||
    request.body?.scope === 'background' || request.get('X-PhishArmor-Mode') === 'premium-background';
}

function consumeRateLimit(ip, premiumBackground, now = Date.now()) {
  const limit = premiumBackground ? premiumLimit : manualLimit;
  const windowMs = premiumBackground ? premiumWindowMs : manualWindowMs;
  const key = `${premiumBackground ? 'premium' : 'manual'}:${ip || 'unknown'}`;
  const current = requestBuckets.get(key);
  const timestamps = (current || []).filter((timestamp) => now - timestamp < windowMs);
  if (timestamps.length >= limit) {
    requestBuckets.set(key, timestamps);
    return false;
  }
  timestamps.push(now);
  requestBuckets.set(key, timestamps);
  if (requestBuckets.size > 10_000) pruneRateLimits(now);
  return true;
}

function pruneRateLimits(now) {
  for (const [key, timestamps] of requestBuckets) {
    const windowMs = key.startsWith('premium:') ? premiumWindowMs : manualWindowMs;
    const active = timestamps.filter((timestamp) => now - timestamp < windowMs);
    if (active.length === 0) requestBuckets.delete(key);
    else requestBuckets.set(key, active);
  }
}

function neutralResult(language, message) {
  return {
    risk_level: 'YELLOW', scam_type: 'safe', confidence_score: 0, detected_language: 'unknown',
    danger_factors: [message], user_alert_message: errorMessages[language] || errorMessages.en,
  };
}

function rateLimitResult(language) {
  const message = limitMessages[language] || limitMessages.en;
  return {
    ...neutralResult(language, message),
    error: 'rate_limit_exceeded',
    danger_factors: [message],
    user_alert_message: message,
  };
}

function classifyVerifiedDomain(text, language) {
  const domains = extractDomains(text);
  const verified = domains.some((domain) => verifiedDomains.has(domain));
  if (!verified || hasCredentialTheftSignals(text)) return null;
  const marketing = /(?:reklām|akcij|piedāv|atlaide|kredīt|mogo|primero|newsletter|promo|sale)/i.test(text);
  const riskLevel = marketing ? 'YELLOW' : 'GREEN';
  const message = marketing
    ? localized(language, 'marketing')
    : localized(language, 'verified');
  return {
    risk_level: riskLevel,
    scam_type: marketing ? 'marketing_spam' : 'safe',
    confidence_score: marketing ? 0.4 : 0.05,
    detected_language: language,
    danger_factors: marketing ? ['Neprasīts mārketinga ziņojums no verificēta domēna.'] : [],
    user_alert_message: message,
  };
}

function extractDomains(text) {
  const domains = [];
  const pattern = /(?:https?:\/\/|www\.)?([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)/gi;
  for (const match of String(text).matchAll(pattern)) domains.push(match[1].toLowerCase().replace(/\.$/, ''));
  return domains;
}

function hasCredentialTheftSignals(text) {
  return /(?:smart[ -]?id|pin\s*[12]|pin2|internetbank|internet bank|bankas parole|parole|verification code|verifikācijas kod)/i.test(text) &&
    /(?:ievad|nosūt|nosūtiet|apstiprin|atklāj|share|enter|confirm|send|код|введите|подтверд)/i.test(text);
}

function localized(language, kind) {
  if (kind === 'marketing') {
    if (language === 'en') return 'An official marketing message, but verify the link before taking action.';
    if (language === 'ru') return 'Официальное маркетинговое сообщение, но проверьте ссылку перед действием.';
    return 'Oficiāls mārketinga ziņojums, tomēr pirms darbības pārbaudiet saites adresi.';
  }
  if (language === 'en') return 'A verified domain was found and no Smart-ID PIN2 or password theft indicators were detected.';
  if (language === 'ru') return 'Обнаружен проверенный домен, признаков кражи Smart-ID PIN2 или пароля нет.';
  return 'Verificēts domēns un nav atrastas Smart-ID PIN2 vai paroles izkrāpšanas pazīmes.';
}

async function analyzeMessage(text, language, inputType, image) {
  const searchPlan = buildSearchPlan(text, inputType);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), upstreamTimeoutMs);
  try {
    const upstreamResponse = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: process.env.PHISHARMOR_OPENAI_MODEL || 'gpt-4o-mini',
        temperature: 0,
        max_tokens: 700,
        response_format: {
          type: 'json_schema',
          json_schema: { name: 'phisharmor_security_analysis', strict: true, schema: analysisSchema },
        },
        messages: [
          { role: 'system', content: buildSystemPrompt(language, inputType) },
          { role: 'user', content: [
            { type: 'text', text: [
              `Input type: ${inputType}`,
              `Normalized phone number: ${searchPlan.normalizedNumber || 'not applicable'}`,
              `Detected region: ${searchPlan.region}`,
              'Regional reputation search queries to consider:',
              ...searchPlan.queries.map((query) => `- ${query}`),
              `Content to analyze:\n${text}`,
            ].join('\n') },
            ...(image ? [{ type: 'image_url', image_url: { url: image.dataUrl, detail: 'low' } }] : []),
          ] },
        ],
      }),
      signal: controller.signal,
    });
    if (!upstreamResponse.ok) throw new Error(`OpenAI request failed with status ${upstreamResponse.status}`);
    const payload = await upstreamResponse.json();
    const content = payload?.choices?.[0]?.message?.content;
    if (typeof content !== 'string') throw new Error('OpenAI response has an invalid shape');
    return validateResult(JSON.parse(content), language);
  } finally {
    clearTimeout(timeout);
  }
}

function buildSystemPrompt(language, inputType) {
  return [
    'You are PhishArmor Core, a professional cybersecurity classification engine.',
    'Reason privately and do not reveal chain-of-thought, hidden reasoning, or internal deliberations. Return only the required JSON object with concise evidence-based conclusions.',
    'Assess the message, OCR content, image text, phone numbers, URLs, and brand claims. Use the supplied regional search queries as investigation leads, but never invent search results or claim verification that was not provided.',
    'RED is reserved for direct, strong, independently verifiable evidence of phishing or confirmed fraud. Unfamiliar numbers, urgency, requests for money or codes, shortened URLs, and unverified complaints are suspicious but not conclusive; use MONITOR and a moderate score.',
    'All unsolicited marketing messages and SMS advertisements from official non-bank lenders such as Primero or Mogo must be YELLOW, never RED, when they do not request Smart-ID PIN2 codes or bank passwords.',
    'Use risk_score from 0.00 to 1.00. Set is_phishing true exactly when risk_score is at least 0.50. Use BLOCK_AND_ALERT only for a clearly confirmed attack, MONITOR for suspicious or unverified activity, and ALLOW only when no meaningful risk indicators exist.',
    `Analyze ${inputType === 'phone_number' ? 'the phone number and its public reputation' : 'the message and any attached image'} for a global audience. Write technical_analysis and user_alert_message_lv in ${languageNames[language]}.`,
    'Return exactly the six schema fields. Keep technical_analysis short, professional, and evidence-based.',
  ].join('\n');
}

function buildSearchPlan(text, inputType) {
  const normalizedNumber = inputType === 'phone_number' ? normalizePhoneNumber(text) : extractPhoneNumber(text);
  const profile = findRegionalProfile(normalizedNumber);
  const subject = normalizedNumber || text.slice(0, 300);
  const queries = profile.terms.map((term) => `${term} ${subject}`);
  queries.push(`scam fraud list ${subject}`, `phone lookup spam ${subject}`);
  if (inputType !== 'phone_number') queries.push(`official domain reputation ${text.slice(0, 180)}`);
  return { normalizedNumber, region: profile.region, queries: [...new Set(queries)].slice(0, 8) };
}

function findRegionalProfile(normalizedNumber) {
  return regionalSearchProfiles
    .flatMap((profile) => profile.prefixes.map((prefix) => ({ profile, prefix })))
    .sort((left, right) => right.prefix.length - left.prefix.length)
    .find(({ prefix }) => normalizedNumber.startsWith(prefix))?.profile || {
      region: 'International / unknown', terms: ['scam fraud report', 'phone lookup spam', 'who called me'],
    };
}

function normalizePhoneNumber(value) {
  const digits = String(value || '').replace(/\D/g, '');
  return digits.length >= 6 ? digits : '';
}

function extractPhoneNumber(value) {
  const match = String(value || '').match(/\+?[\d][\d\s().-]{5,}[\d]/);
  return match ? normalizePhoneNumber(match[0]) : '';
}

function validateText(value) {
  if (typeof value !== 'string' || !value.trim()) throw badRequest('"text" must be a non-empty string');
  if (value.length > maxTextLength) throw badRequest(`"text" must be at most ${maxTextLength} characters`);
  return value.trim();
}

function validateInputType(value) {
  if (value === undefined) return 'message';
  if (typeof value !== 'string' || !allowedInputTypes.has(value)) {
    throw badRequest('"input_type" must be one of: message, phone_number, call_transcript');
  }
  return value;
}

function validateImage(value, mimeType = 'image/jpeg') {
  if (value == null || value === '') return null;
  if (typeof value !== 'string' || value.length > maxImageBase64Length) {
    throw badRequest('"image_base64" must contain an image no larger than 2 MB');
  }
  if (!allowedImageTypes.has(mimeType)) {
    throw badRequest('"image_mime_type" must be image/jpeg, image/png, or image/webp');
  }
  const base64 = value.replace(/^data:image\/(jpeg|png|webp);base64,/i, '');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(base64) || base64.length < 16 || base64.length % 4 === 1) {
    throw badRequest('"image_base64" must contain valid base64 image data');
  }
  const byteLength = Buffer.byteLength(base64, 'base64');
  if (byteLength > maxImageBytes) throw badRequest('"image_base64" must contain an image no larger than 2 MB');
  return { dataUrl: `data:${mimeType};base64,${base64}` };
}

function validateResult(value, language) {
  if (
    !value || typeof value !== 'object' || !Array.isArray(value.scam_indicators_found) ||
    value.scam_indicators_found.length > 12 ||
    value.scam_indicators_found.some((indicator) => typeof indicator !== 'string' || !indicator.trim()) ||
    typeof value.technical_analysis !== 'string' || !value.technical_analysis.trim() ||
    typeof value.risk_score !== 'number' || !Number.isFinite(value.risk_score) ||
    value.risk_score < 0 || value.risk_score > 1 ||
    typeof value.is_phishing !== 'boolean' || value.is_phishing !== (value.risk_score >= 0.5) ||
    !['BLOCK_AND_ALERT', 'MONITOR', 'ALLOW'].includes(value.action_required) ||
    typeof value.user_alert_message_lv !== 'string' || !value.user_alert_message_lv.trim()
  ) throw new Error('OpenAI response did not match the expected schema');
  const riskLevel = value.risk_score >= 0.75 || value.action_required === 'BLOCK_AND_ALERT'
    ? 'RED'
    : value.risk_score >= 0.35 || value.action_required === 'MONITOR'
    ? 'YELLOW'
    : 'GREEN';
  const indicators = value.scam_indicators_found.map((factor) => factor.trim().slice(0, 240));
  return {
    risk_level: riskLevel,
    scam_type: inferScamType(indicators, riskLevel),
    confidence_score: value.risk_score,
    detected_language: language,
    danger_factors: indicators.length > 0 ? indicators : [value.technical_analysis.trim().slice(0, 240)],
    user_alert_message: value.user_alert_message_lv.trim().slice(0, 360),
  };
}

function inferScamType(indicators, riskLevel) {
  if (riskLevel === 'GREEN') return 'safe';
  const text = indicators.join(' ').toLowerCase();
  if (/url|link|domain|saite|saiti|vietne/.test(text)) return 'phishing_url';
  if (/bank|brand|imperson|zīm|banka|kurjer/.test(text)) return 'impersonation';
  if (/invest|crypto|ieguld|investīc/.test(text)) return 'investment_scam';
  if (/delivery|piegād|parcel|pak/.test(text)) return 'delivery_fake';
  if (/urgent|urgenc|steidz|threat|draud/.test(text)) return 'urgency_extortion';
  if (/spam|marketing|reklām/.test(text)) return 'marketing_spam';
  return 'safe';
}

function badRequest(message) {
  const error = new Error(message);
  error.statusCode = 400;
  return error;
}

app.listen(port, '0.0.0.0', () => console.log(`PhishArmor proxy listening on port ${port}`));
