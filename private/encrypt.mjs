/* ---------- Шифрование писем ----------
   Запуск (нужен Node.js 18+):   node private/encrypt.mjs
   Скрипт спросит пароль (ввод не отображается), зашифрует letters.src.mjs
   и запишет результат в letters.enc в корне сайта.

   Как это устроено:
     • ключ получается из пароля через PBKDF2-SHA256 (1 000 000 итераций, случайная соль);
     • письма шифруются AES-256-GCM (случайный IV) — это шифрование с проверкой подлинности,
       поэтому неверный пароль или подмена файла просто не расшифруются;
     • размер данных выравнивается до 4 КБ, чтобы длина файла не выдавала объём писем;
     • в конце скрипт сам расшифровывает файл тем же способом, что и браузер, и сверяет результат.

   Пароль в командной строке не передаём — он попадёт в историю команд.
   (Для автоматизации можно задать переменную окружения LETTERS_PASSWORD.) */

import { createCipheriv, pbkdf2Sync, randomBytes, webcrypto } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const ITER = 1_000_000;          // можно увеличить; браузер берёт значение из файла
const AAD = "letters-v1";        // должно совпадать с index.html
const MIN_LEN = 12;
const PAD = 4096;

const here = dirname(fileURLToPath(import.meta.url));
const OUT = resolve(here, "..", "letters.enc");

/* ввод пароля без отображения */
function askHidden(q) {
  return new Promise(res => {
    const { stdin, stdout } = process;
    stdout.write(q);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    let s = "";
    const on = chunk => {
      for (const c of chunk) {
        if (c === "\r" || c === "\n") {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.off("data", on);
          stdout.write("\n");
          return res(s);
        }
        if (c === "\u0003") { stdout.write("\n"); process.exit(130); }
        if (c === "\u007f" || c === "\b") s = s.slice(0, -1);
        else if (c >= " ") s += c;
      }
    };
    stdin.on("data", on);
  });
}

function fail(msg) { console.error("Ошибка: " + msg); process.exit(1); }

/* 1. письма */
const { default: letters } = await import(pathToFileURL(resolve(here, "letters.src.mjs")).href);
if (!Array.isArray(letters) || !letters.length) fail("в letters.src.mjs должен быть непустой список писем");
letters.forEach((l, i) => {
  if (typeof l.title !== "string" || typeof l.text !== "string") fail(`у письма №${i + 1} нужны строки title и text`);
});

/* 2. пароль */
let password = process.env.LETTERS_PASSWORD;
if (!password) {
  if (!process.stdin.isTTY) fail("нет терминала. Запустите в обычном терминале или задайте LETTERS_PASSWORD");
  password = await askHidden("Пароль (код доступа): ");
  const again = await askHidden("Повторите пароль:      ");
  if (password !== again) fail("пароли не совпали");
}
if ([...password].length < MIN_LEN) {
  fail(`пароль слишком короткий (минимум ${MIN_LEN} символов). Лучше фраза из 4–5 слов — файл letters.enc публичный, и его можно перебирать без ограничений.`);
}

/* 3. шифрование */
const salt = randomBytes(16);
const iv = randomBytes(12);
const keyBytes = pbkdf2Sync(Buffer.from(password.normalize("NFKC"), "utf8"), salt, ITER, 32, "sha256");

let json = JSON.stringify(letters);
const size = Buffer.byteLength(json);
json += " ".repeat(Math.ceil((size + 1) / PAD) * PAD - size);   // пробелы в конце JSON не мешают разбору

const cipher = createCipheriv("aes-256-gcm", keyBytes, iv);
cipher.setAAD(Buffer.from(AAD));
const data = Buffer.concat([cipher.update(json, "utf8"), cipher.final(), cipher.getAuthTag()]);

const file = {
  v: 1,
  iter: ITER,
  salt: salt.toString("base64"),
  iv: iv.toString("base64"),
  data: data.toString("base64")
};
writeFileSync(OUT, JSON.stringify(file));

/* 4. проверка тем же способом, что в браузере (Web Crypto) */
const { subtle } = webcrypto;
const b64 = s => Uint8Array.from(Buffer.from(s, "base64"));
const enc = new TextEncoder();
const base = await subtle.importKey("raw", enc.encode(password.normalize("NFKC")), "PBKDF2", false, ["deriveKey"]);
const key = await subtle.deriveKey(
  { name: "PBKDF2", hash: "SHA-256", salt: b64(file.salt), iterations: file.iter },
  base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
);
const plain = await subtle.decrypt(
  { name: "AES-GCM", iv: b64(file.iv), additionalData: enc.encode(AAD) }, key, b64(file.data)
);
if (JSON.stringify(JSON.parse(new TextDecoder().decode(plain))) !== JSON.stringify(letters)) {
  fail("проверка не прошла: расшифрованные данные не совпали");
}

console.log(`Готово: ${letters.length} пис. → ${OUT}`);
console.log("Проверка расшифровки пройдена. Выкладывайте на сайт letters.enc, но НЕ папку private.");
