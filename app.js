/* =========================================================
   Persian-look Encoder / Decoder
   Works fully client-side (GitHub Pages compatible)
   ========================================================= */

/* ---------- Base64URL alphabet (64 chars) ---------- */
const B64URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* ---------- Persian-look UNIQUE 64-char mapping ---------- */
const FA_MAP = [
  // 32 letters
  "ا","ب","پ","ت","ث","ج","چ","ح","خ","د","ذ","ر","ز","ژ","س","ش",
  "ص","ض","ط","ظ","ع","غ","ف","ق","ک","گ","ل","م","ن","و","ه","ی",

  // 10 Persian digits
  "۰","۱","۲","۳","۴","۵","۶","۷","۸","۹",

  // 10 Arabic digits (different Unicode)
  "٠","١","٢","٣","٤","٥","٦","٧","٨","٩",

  // 12 extra unique chars
  "ء","آ","أ","ؤ","إ","ئ","ة","ۀ","َ","ُ","ِ","ّ"
];

/* ---------- Safety check ---------- */
if (FA_MAP.length !== 64 || new Set(FA_MAP).size !== 64) {
  throw new Error("FA_MAP must contain exactly 64 UNIQUE characters.");
}

/* ---------- Build maps ---------- */
const toFa = new Map();
const fromFa = new Map();

for (let i = 0; i < 64; i++) {
  toFa.set(B64URL_ALPHABET[i], FA_MAP[i]);
  fromFa.set(FA_MAP[i], B64URL_ALPHABET[i]);
}

/* ---------- Prefixes ---------- */
const PREFIX_NOPASS = "فص:";
const PREFIX_PASS = "فپ:";

/* ---------- Helpers ---------- */
const $ = (id) => document.getElementById(id);

function setStatus(msg, isError = false) {
  const el = $("status");
  el.textContent = msg;
  el.style.color = isError ? "#ff6b6b" : "";
  setTimeout(() => {
    el.textContent = "";
    el.style.color = "";
  }, 3500);
}

function bytesToBase64Url(bytes) {
  let binary = "";
  bytes.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64UrlToBytes(b64url) {
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  const binary = atob(b64);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function base64UrlToFa(b64url) {
  return [...b64url].map((c) => toFa.get(c)).join("");
}

function faToBase64Url(faText) {
  return [...faText].map((c) => fromFa.get(c)).join("");
}

/* =========================================================
   No-password mode (reversible obfuscation)
   ========================================================= */
function encodeNoPass(text) {
  const bytes = new TextEncoder().encode(text);
  const b64url = bytesToBase64Url(bytes);
  return PREFIX_NOPASS + base64UrlToFa(b64url);
}

function decodeNoPass(encoded) {
  if (!encoded.startsWith(PREFIX_NOPASS))
    throw new Error("Invalid prefix");
  const fa = encoded.slice(PREFIX_NOPASS.length);
  const b64url = faToBase64Url(fa);
  const bytes = base64UrlToBytes(b64url);
  return new TextDecoder().decode(bytes);
}

/* =========================================================
   Password mode (AES-GCM)
   ========================================================= */
async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 150000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encodeWithPass(text, password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(text)
  );

  const cipherBytes = new Uint8Array(encrypted);
  const packed = new Uint8Array(16 + 12 + cipherBytes.length);

  packed.set(salt, 0);
  packed.set(iv, 16);
  packed.set(cipherBytes, 28);

  const b64url = bytesToBase64Url(packed);
  return PREFIX_PASS + base64UrlToFa(b64url);
}

async function decodeWithPass(encoded, password) {
  if (!encoded.startsWith(PREFIX_PASS))
    throw new Error("Invalid prefix");

  const fa = encoded.slice(PREFIX_PASS.length);
  const b64url = faToBase64Url(fa);
  const packed = base64UrlToBytes(b64url);

  const salt = packed.slice(0, 16);
  const iv = packed.slice(16, 28);
  const data = packed.slice(28);

  const key = await deriveKey(password, salt);
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    data
  );

  return new TextDecoder().decode(new Uint8Array(decrypted));
}

/* =========================================================
   UI Logic
   ========================================================= */
let mode = "nopass";

function setMode(m) {
  mode = m;
  $("modeNoPass").classList.toggle("active", m === "nopass");
  $("modeWithPass").classList.toggle("active", m === "pass");
  $("passRow").classList.toggle("hidden", m !== "pass");
}

$("modeNoPass").onclick = () => setMode("nopass");
$("modeWithPass").onclick = () => setMode("pass");

$("encodeBtn").onclick = async () => {
  try {
    const input = $("input").value;
    if (!input.trim()) return setStatus("ورودی خالی است", true);

    if (mode === "nopass") {
      $("output").value = encodeNoPass(input);
    } else {
      const pass = $("password").value;
      if (!pass) return setStatus("پسورد لازم است", true);
      $("output").value = await encodeWithPass(input, pass);
    }
    setStatus("کدگذاری انجام شد ✅");
  } catch (e) {
    setStatus("خطا: " + e.message, true);
  }
};

$("decodeBtn").onclick = async () => {
  try {
    const input = $("input").value;
    if (!input.trim()) return setStatus("ورودی خالی است", true);

    if (input.startsWith(PREFIX_PASS)) {
      const pass = $("password").value;
      if (!pass) return setStatus("پسورد لازم است", true);
      $("output").value = await decodeWithPass(input, pass);
    } else {
      $("output").value = decodeNoPass(input);
    }
    setStatus("بازگشایی شد ✅");
  } catch (e) {
    setStatus("خطا: متن یا پسورد اشتباه است", true);
  }
};

$("copyBtn").onclick = async () => {
  await navigator.clipboard.writeText($("output").value);
  setStatus("کپی شد 📋");
};

$("swapBtn").onclick = () => {
  [$("input").value, $("output").value] = [
    $("output").value,
    $("input").value,
  ];
};

$("clearBtn").onclick = () => {
  $("input").value = "";
  $("output").value = "";
};

/* ---------- Default ---------- */
setMode("nopass");
