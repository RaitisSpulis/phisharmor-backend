const crypto = require('node:crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
const port = Number(process.env.PORT) || 3000;
const upstreamTimeoutMs = 25_000;
const maxTextLength = 10_000;
const allowedLanguages = new Set(['lv', 'en', 'ru']);
const allowedInputTypes = new Set(['message', 'phone_number', 'call_transcript']);
const allowedOrigins = new Set(
  (process.env.ALLOWED_ORIGINS || '').split(',').map((origin) => origin.trim()).filter(Boolean),
);
const clientApiKey = process.env.PHISHARMOR_API_KEY?.trim() || '';
const mobileClientName = 'phisharmor-android';
const allowedRiskLevels = new Set(['RED', 'YELLOW', 'GREEN']);
const allowedEvidenceLevels = new Set(['confirmed_direct', 'suspicious_or_unverified', 'no_risk_found']);
const allowedScamTypes = new Set([
  'phishing_url', 'impersonation', 'urgency_extortion', 'investment_scam',
  'delivery_fake', 'marketing_spam', 'safe',
]);
const languageNames = { lv: 'latviešu', en: 'angļu', ru: 'krievu' };

const analysisSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    risk_level: { type: 'string', enum: ['RED', 'YELLOW', 'GREEN'] },
    evidence_level: { type: 'string', enum: ['confirmed_direct', 'suspicious_or_unverified', 'no_risk_found'] },
    scam_type: { type: 'string', enum: [
      'phishing_url', 'impersonation', 'urgency_extortion', 'investment_scam',
      'delivery_fake', 'marketing_spam', 'safe',
    ] },
    confidence_score: { type: 'number', minimum: 0, maximum: 1 },
    detected_language: { type: 'string', minLength: 1, maxLength: 80 },
    danger_factors: {
      type: 'array', items: { type: 'string', minLength: 1, maxLength: 240 }, maxItems: 8,
    },
    user_alert_message: { type: 'string', minLength: 1, maxLength: 360 },
  },
  required: [
    'risk_level', 'evidence_level', 'scam_type', 'confidence_score', 'detected_language',
    'danger_factors', 'user_alert_message',
  ],
};

const errorMessages = {
  lv: 'Drošības pārbaudi neizdevās pabeigt. Lūdzu, mēģiniet vēlreiz un neklikšķiniet uz saitēm, kamēr ziņa nav pārbaudīta.',
  en: 'The security check could not be completed. Please try again and do not click links until the message is checked.',
  ru: 'Не удалось завершить проверку безопасности. Повторите попытку и не нажимайте на ссылки, пока сообщение не проверено.',
};

const regionalSearchProfiles = [
  { prefixes: ['371'], region: 'Latvia', terms: ['scam', 'kas zvanīja', 'krāpnieki'] },
  { prefixes: ['370'], region: 'Lithuania', terms: ['scam', 'kas skambino', 'sukčiai'] },
  { prefixes: ['372'], region: 'Estonia', terms: ['scam', 'kes helistas', 'pettus'] },
  { prefixes: ['44'], region: 'United Kingdom', terms: ['who called me', 'scam lookup', 'fraud report'] },
  { prefixes: ['1'], region: 'United States or Canada', terms: ['scam report', 'who called', 'spam call'] },
  { prefixes: ['33'], region: 'France', terms: ['numéro arnaque', 'qui m\'a appelé', 'appel spam'] },
  { prefixes: ['49'], region: 'Germany', terms: ['Betrugsnummer', 'wer hat angerufen', 'Spam Anruf'] },
  { prefixes: ['34'], region: 'Spain', terms: ['número estafa', 'quién me llamó', 'llamada spam'] },
  { prefixes: ['39'], region: 'Italy', terms: ['numero truffa', 'chi mi ha chiamato', 'chiamata spam'] },
  { prefixes: ['81'], region: 'Japan', terms: ['迷惑電話', '詐欺電話', '誰からの電話'] },
  { prefixes: ['86'], region: 'China', terms: ['诈骗电话', '骚扰电话', '谁打来的'] },
  { prefixes: ['91'], region: 'India', terms: ['scam number', 'who called', 'spam call'] },
  { prefixes: ['7'], region: 'Russia or Kazakhstan', terms: ['номер мошенники', 'кто звонил', 'спам звонок'] },
];

app.disable('x-powered-by');
app.use(helmet());
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.has(origin)) return callback(null, true);
    return callback(new Error('CORS origin denied'));
  },
  allowedHeaders: ['Content-Type', 'X-PhishArmor-Key', 'X-PhishArmor-App'],
  methods: ['GET', 'POST', 'OPTIONS'],
}));
app.use(express.json({ limit: '32kb' }));

if (!clientApiKey && allowedOrigins.size === 0) {
  console.error('No ALLOWED_ORIGINS or PHISHARMOR_API_KEY configured; all analysis requests will be denied.');
}

app.get('/health', (_request, response) => response.json({ status: 'ok' }));

app.post(['/','/check-sms'], async (request, response, next) => {
  try {
    if (!isAuthorizedRequest(request)) {
      return response.status(403).json(neutralResult('en', 'Request not authorized'));
    }
    if (!process.env.OPENAI_API_KEY) throw new Error('OPENAI_API_KEY is not configured');
    const text = validateText(request.body?.text ?? request.body?.input_text);
    const language = validateLanguage(request.body?.language ?? request.body?.lang);
    const inputType = validateInputType(request.body?.input_type);
    return response.json(await analyzeMessage(text, language, inputType));
  } catch (error) {
    return next(error);
  }
});

app.use((_request, response) => response.status(404).json(neutralResult('en', 'Endpoint not found')));

app.use((error, request, response, _next) => {
  const statusCode = error?.type === 'entity.parse.failed'
    ? 400
    : Number.isInteger(error?.statusCode) ? error.statusCode : 502;
  const requestedLanguage = request.body?.language ?? request.body?.lang;
  const language = allowedLanguages.has(requestedLanguage) ? requestedLanguage : 'en';
  const publicMessage = statusCode === 400 ? 'Request body must be valid JSON.' : errorMessages[language];
  console.error('Request failed:', error?.message || 'Unknown server error');
  response.status(statusCode).json(neutralResult(language, publicMessage));
});

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

function neutralResult(language, message) {
  return {
    risk_level: 'YELLOW', scam_type: 'safe', confidence_score: 0, detected_language: 'unknown',
    danger_factors: [message], user_alert_message: errorMessages[language] || errorMessages.en,
  };
}

async function analyzeMessage(text, language, inputType) {
  const searchPlan = buildSearchPlan(text, inputType);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), upstreamTimeoutMs);
  try {
    const upstreamResponse = await fetch('https://api.openai.com/v1/responses', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: process.env.PHISHARMOR_OPENAI_MODEL || 'gpt-4o-mini',
        tools: [{ type: 'web_search_preview' }],
        tool_choice: 'required',
        max_output_tokens: 700,
        text: { format: {
          type: 'json_schema', name: 'phisharmor_security_analysis', strict: true, schema: analysisSchema,
        } },
        input: [
          {
            role: 'system',
            content: [{ type: 'input_text', text: buildSystemPrompt(language, inputType) }],
          },
          {
            role: 'user',
            content: [{ type: 'input_text', text: [
              `Input type: ${inputType}`,
              `Normalized phone number: ${searchPlan.normalizedNumber || 'not applicable'}`,
              `Detected region: ${searchPlan.region}`,
              'Mandatory search queries:',
              ...searchPlan.queries.map((query) => `- ${query}`),
              `Content to analyze:\n${text}`,
            ].join('\n') }],
          },
        ],
      }),
      signal: controller.signal,
    });
    if (!upstreamResponse.ok) throw new Error(`OpenAI request failed with status ${upstreamResponse.status}`);
    const payload = await upstreamResponse.json();
    const content = extractResponseText(payload);
    if (typeof content !== 'string') throw new Error('OpenAI response has an invalid shape');
    return validateResult(JSON.parse(content));
  } finally {
    clearTimeout(timeout);
  }
}

function buildSystemPrompt(language, inputType) {
  return [
    'You are the PhishArmor global cybersecurity engine.',
    'You MUST use web_search_preview before final classification. Do not return final JSON until live web search has executed using the supplied queries.',
    'Search globally across multiple languages and reliable complaint, fraud-report, telecom, domain, and official brand sources. Never expose personal data from search results.',
    'Risk policy is strict and conservative to prevent false alarms:',
    'RED is allowed ONLY when there is direct, conclusive, independently verifiable evidence of an actual scam attack. Examples include a URL that is an unmistakable brand impersonation and does not match the official domain, or a phone number directly identified as fraudulent by a reliable public registry or official source.',
    'A single vague complaint, a search result saying possible scam, an unfamiliar number, an international number, urgency, unusual wording, a request for money or codes, a shortened URL, a suspicious redirect, or a lookalike that is not conclusively verified is NOT enough for RED.',
    'When evidence is incomplete, ambiguous, unverified, or can only be described as possible fraud, potential spam, suspicious activity, or likely scam, you MUST use risk_level YELLOW and evidence_level suspicious_or_unverified.',
    'Use GREEN only when the content or contact is ordinary and no meaningful risk indicators are present after the required search. Do not infer safety merely because no search result was found.',
    'For RED, evidence_level MUST be confirmed_direct. For YELLOW, evidence_level MUST be suspicious_or_unverified. For GREEN, evidence_level MUST be no_risk_found. Never claim 100% certainty from weak or indirect evidence.',
    `Analyze ${inputType === 'phone_number' ? 'the phone number and its public reputation' : 'the message, OCR content, phone numbers, URLs, and brand claims'} for a global audience.`,
    `Write danger_factors and user_alert_message in ${languageNames[language]}. detected_language must describe the original input language.`,
    'Return only the required Structured Outputs object with risk_level, evidence_level, scam_type, confidence_score, detected_language, danger_factors, and user_alert_message.',
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

function extractResponseText(payload) {
  if (typeof payload?.output_text === 'string') return payload.output_text;
  if (!Array.isArray(payload?.output)) return undefined;
  for (const item of payload.output) {
    if (!Array.isArray(item?.content)) continue;
    const textPart = item.content.find((part) => part?.type === 'output_text');
    if (typeof textPart?.text === 'string') return textPart.text;
  }
  return undefined;
}

function validateText(value) {
  if (typeof value !== 'string' || !value.trim()) throw badRequest('"text" must be a non-empty string');
  if (value.length > maxTextLength) throw badRequest(`"text" must be at most ${maxTextLength} characters`);
  return value.trim();
}

function validateLanguage(value) {
  if (typeof value !== 'string' || !allowedLanguages.has(value)) throw badRequest('"language" must be one of: lv, en, ru');
  return value;
}

function validateInputType(value) {
  if (value === undefined) return 'message';
  if (typeof value !== 'string' || !allowedInputTypes.has(value)) {
    throw badRequest('"input_type" must be one of: message, phone_number, call_transcript');
  }
  return value;
}

function validateResult(value) {
  const evidenceLevel = value?.evidence_level;
  if (
    !value || typeof value !== 'object' || !allowedRiskLevels.has(value.risk_level) ||
    !allowedEvidenceLevels.has(evidenceLevel) ||
    !allowedScamTypes.has(value.scam_type) || typeof value.confidence_score !== 'number' ||
    !Number.isFinite(value.confidence_score) || value.confidence_score < 0 || value.confidence_score > 1 ||
    typeof value.detected_language !== 'string' || !value.detected_language.trim() ||
    !Array.isArray(value.danger_factors) || value.danger_factors.length > 8 ||
    value.danger_factors.some((factor) => typeof factor !== 'string' || !factor.trim()) ||
    typeof value.user_alert_message !== 'string' || !value.user_alert_message.trim()
  ) throw new Error('OpenAI response did not match the expected schema');
  const riskLevel = evidenceLevel === 'confirmed_direct' && value.risk_level === 'RED'
    ? 'RED'
    : evidenceLevel === 'no_risk_found' && value.risk_level === 'GREEN'
    ? 'GREEN'
    : 'YELLOW';
  return {
    risk_level: riskLevel, evidence_level: evidenceLevel, scam_type: value.scam_type, confidence_score: value.confidence_score,
    detected_language: value.detected_language.trim().slice(0, 80),
    danger_factors: value.danger_factors.map((factor) => factor.trim().slice(0, 240)),
    user_alert_message: value.user_alert_message.trim().slice(0, 360),
  };
}

function badRequest(message) {
  const error = new Error(message);
  error.statusCode = 400;
  return error;
}

app.listen(port, '0.0.0.0', () => console.log(`PhishArmor proxy listening on port ${port}`));