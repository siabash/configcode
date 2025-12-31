// =======================
// Persian-look mapping (reversible)
// =======================

// یک alphabet فارسی‌نما برای نمایش (فقط برای ظاهر).
// ما bytes را به base64url تبدیل می‌کنیم و بعد هر کاراکتر را به یک کاراکتر فارسی‌نما نگاشت می‌کنیم.
const b64urlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const faAlphabet     = "ابتثجچحخدذرزژسشصضطظعغفقکگلمنوهیپتژگسشعفقلمنوهیپ"; 
// بالا ممکن است تکرار داشته باشد؛ پس ما به جای این، از مجموعه یونیک و کافی استفاده می‌کنیم:

const faMapFrom = b64urlAlphabet.split("");
const faMapTo   = [
  "ا","ب","پ","ت","ث","ج","چ","ح","خ","د","ذ","ر","ز","ژ","س","ش","ص","ض","ط","ظ","ع","غ",
  "ف","ق","ک","گ","ل","م","ن","و","ه","ی",
  "آ","ؤ","ئ","ة","ۀ","ء","ی","ک","گ","پ","چ","ژ","ڤ","۰","۱","۲","۳","۴","۵","۶","۷","۸","۹",
  "ـ","ً","ٌ"
]; // 64 تایی

if (faMapTo.length !== 64) {
  console.warn("faMapTo must be length 64, current:", faMapTo.length);
}

const toFa = new Map();
const fromFa = new Map();
for (let i = 0; i < 64; i++) {
  toFa.set(faMapFrom[i], faMapTo[i]);
  fromFa.set(faMapTo[i], faMapFrom[i]);
}

// Prefix برای تشخیص نوع خروجی
const PREFIX_NOPASS = "فص:";  // یعنی فارسی‌نما، ساده
const PREFIX_PASS   = "فپ:";  // یعنی فارسی‌نما، با پسورد

// =======================
// Helpers
// =======================
const $ = (id) => document.getElementById(id);

function setStatus(msg, isErr=false){
  const el = $("status");
  el.textContent = msg;
  el.style.color = isErr ? "var(--danger)" : "";
  setTimeout(() => { el.textContent = ""; el.style.color=""; }, 3500);
}

function bytesToB64Url(bytes){
  // bytes -> base64 -> base64url
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  const b64 = btoa(binary);
  return b64.replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
}
function b64UrlToBytes(b64url){
  let b64 = b64url.replaceAll("-","+").replaceAll("_","/");
  // pad
  while (b64.length % 4) b64 += "=";
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i=0;i<binary.length;i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function b64UrlToFa(b64url){
  let out = "";
  for (const ch of b64url){
    const mapped = toFa.get(ch);
    if (!mapped) throw new Error("Unexpected base64url char: " + ch);
    out += mapped;
  }
  return out;
}
function faToB64Url(faText){
  let out = "";
  for (const ch of faText){
    const mapped = fromFa.get(ch);
    if (!mapped) throw new Error("Invalid encoded char: " + ch);
    out += mapped;
  }
  return out;
}

// =======================
// No-password mode (reversible obfuscation)
// =======================
function encodeNoPass(plainText){
  const bytes = new TextEncoder().encode(plainText);
  const b64url = bytesToB64Url(bytes);
  const fa = b64UrlToFa(b64url);
  return PREFIX_NOPASS + fa;
}
function decodeNoPass(encoded){
  if (!encoded.startsWith(PREFIX_NOPASS)) throw new Error("Prefix mismatch");
  const fa = encoded.slice(PREFIX_NOPASS.length);
  const b64url = faToB64Url(fa);
  const bytes = b64UrlToBytes(b64url);
  return new TextDecoder().decode(bytes);
}

// =======================
// With-password mode (AES-GCM)
// =======================
async function deriveKeyFromPassword(password, salt){
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    { name:"PBKDF2", salt, iterations: 150000, hash:"SHA-256" },
    keyMaterial,
    { name:"AES-GCM", length: 256 },
    false,
    ["encrypt","decrypt"]
  );
}

async function encodeWithPass(plainText, password){
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveKeyFromPassword(password, salt);

  const cipher = await crypto.subtle.encrypt(
    { name:"AES-GCM", iv },
    key,
    enc.encode(plainText)
  );

  // Pack: salt(16) + iv(12) + cipherBytes
  const cipherBytes = new Uint8Array(cipher);
  const packed = new Uint8Array(16 + 12 + cipherBytes.length);
  packed.set(salt, 0);
  packed.set(iv, 16);
  packed.set(cipherBytes, 28);

  const b64url = bytesToB64Url(packed);
  const fa = b64UrlToFa(b64url);
  return PREFIX_PASS + fa;
}

async function decodeWithPass(encoded, password){
  if (!encoded.startsWith(PREFIX_PASS)) throw new Error("Prefix mismatch");
  const fa = encoded.slice(PREFIX_PASS.length);
  const b64url = faToB64Url(fa);
  const packed = b64UrlToBytes(b64url);

  const salt = packed.slice(0,16);
  const iv   = packed.slice(16,28);
  const data = packed.slice(28);

  const key = await deriveKeyFromPassword(password, salt);

  const plainBuf = await crypto.subtle.decrypt(
    { name:"AES-GCM", iv },
    key,
    data
  );

  return new TextDecoder().decode(new Uint8Array(plainBuf));
}

// =======================
// UI logic
// =======================
let mode = "nopass"; // "nopass" | "pass"

function setMode(newMode){
  mode = newMode;
  $("modeNoPass").classList.toggle("active", mode==="nopass");
  $("modeWithPass").classList.toggle("active", mode==="pass");
  $("passRow").classList.toggle("hidden", mode!=="pass");
}

$("modeNoPass").addEventListener("click", () => setMode("nopass"));
$("modeWithPass").addEventListener("click", () => setMode("pass"));

$("encodeBtn").addEventListener("click", async () => {
  try{
    const input = $("input").value ?? "";
    if (!input.trim()) return setStatus("ورودی خالیه.", true);

    if (mode === "nopass"){
      $("output").value = encodeNoPass(input);
      setStatus("کدگذاری شد ✅");
    } else {
      const pass = $("password").value ?? "";
      if (!pass) return setStatus("پسورد رو وارد کن.", true);
      $("output").value = await encodeWithPass(input, pass);
      setStatus("رمزنگاری شد ✅");
    }
  } catch(e){
    setStatus("خطا: " + (e?.message || e), true);
  }
});

$("decodeBtn").addEventListener("click", async () => {
  try{
    const input = $("input").value ?? "";
    if (!input.trim()) return setStatus("ورودی خالیه.", true);

    if (input.startsWith(PREFIX_PASS)){
      const pass = $("password").value ?? "";
      if (!pass) return setStatus("این متن با پسورد ساخته شده؛ پسورد لازم است.", true);
      $("output").value = await decodeWithPass(input, pass);
      setStatus("بازگشایی شد ✅");
      return;
    }
    if (input.startsWith(PREFIX_NOPASS)){
      $("output").value = decodeNoPass(input);
      setStatus("بازگشایی شد ✅");
      return;
    }

    // اگر کاربر prefix نداد: حدس بزن nopass
    $("output").value = decodeNoPass(input);
    setStatus("بازگشایی شد ✅ (بدون پسورد)");
  } catch(e){
    setStatus("خطا: " + (e?.message || e), true);
  }
});

$("copyBtn").addEventListener("click", async () => {
  try{
    await navigator.clipboard.writeText($("output").value || "");
    setStatus("کپی شد ✅");
  } catch {
    setStatus("کپی ناموفق بود. دستی کپی کن.", true);
  }
});

$("swapBtn").addEventListener("click", () => {
  const a = $("input").value;
  $("input").value = $("output").value;
  $("output").value = a;
  setStatus("جابجا شد ↔️");
});

$("clearBtn").addEventListener("click", () => {
  $("input").value = "";
  $("output").value = "";
  setStatus("پاک شد");
});

// default
setMode("nopass");
