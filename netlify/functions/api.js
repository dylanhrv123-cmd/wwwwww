const crypto = require("crypto");

const SESSION_DAYS = 30;
const EMPTY = { events: [], tasks: [], notes: [], habits: [] };

const json = (status, body) => ({
  statusCode: status,
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

const parseBody = (event) => {
  try { return JSON.parse(event.body || "{}"); } catch (e) { return {}; }
};

const validEmail = (e) => typeof e === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

// La base de datos se abre solo cuando se necesita, para que un error aquí
// se muestre en la pantalla con su mensaje en lugar de un 502.
function store() {
  const { getStore } = require("@netlify/blobs");
  const siteID = process.env.BLOBS_SITE_ID;
  const token = process.env.BLOBS_TOKEN;
  // Si las variables existen, se usan directamente; si no, Netlify intenta configurarlo solo.
  if (siteID && token) return getStore({ name: "organizacion-vida", siteID, token });
  return getStore("organizacion-vida");
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

function checkPassword(password, salt, hash) {
  const test = crypto.scryptSync(password, salt, 64);
  const real = Buffer.from(hash, "hex");
  return test.length === real.length && crypto.timingSafeEqual(test, real);
}

async function newSession(st, userId) {
  const token = crypto.randomBytes(32).toString("hex");
  await st.setJSON(`session:${token}`, {
    userId,
    exp: Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000,
  });
  return { token };
}

async function getSession(st, event) {
  const header = event.headers.authorization || event.headers.Authorization || "";
  const token = header.replace(/^Bearer\s+/i, "");
  if (!token || token.length < 32) return null;
  const s = await st.get(`session:${token}`, { type: "json" });
  if (!s || s.exp < Date.now()) return null;
  return { token, userId: s.userId };
}

function cleanData(input) {
  const out = { ...EMPTY };
  for (const key of Object.keys(EMPTY)) {
    if (Array.isArray(input && input[key])) out[key] = input[key];
  }
  return out;
}

exports.handler = async (event) => {
  const path = event.path.replace(/^.*\/api/, "").replace(/\/$/, "");
  const method = event.httpMethod;

  try {
    const st = store();

    if (path === "/register" && method === "POST") {
      const { email: rawEmail, password } = parseBody(event);
      const email = String(rawEmail || "").trim().toLowerCase();
      if (!validEmail(email)) return json(400, { error: "Escribe un correo válido." });
      if (typeof password !== "string" || password.length < 6)
        return json(400, { error: "La contraseña debe tener al menos 6 caracteres." });

      const key = `user:${email}`;
      if (await st.get(key, { type: "json" }))
        return json(409, { error: "Ya existe una cuenta con ese correo." });

      const userId = crypto.randomUUID();
      const { salt, hash } = hashPassword(password);
      await st.setJSON(key, { userId, salt, hash });
      await st.setJSON(`data:${userId}`, EMPTY);
      return json(200, await newSession(st, userId));
    }

    if (path === "/login" && method === "POST") {
      const { email: rawEmail, password } = parseBody(event);
      const email = String(rawEmail || "").trim().toLowerCase();
      const u = await st.get(`user:${email}`, { type: "json" });
      if (!u || typeof password !== "string" || !checkPassword(password, u.salt, u.hash))
        return json(401, { error: "Correo o contraseña incorrectos." });
      return json(200, await newSession(st, u.userId));
    }

    if (path === "/logout" && method === "POST") {
      const s = await getSession(st, event);
      if (s) await st.delete(`session:${s.token}`);
      return json(200, { ok: true });
    }

    if (path === "/data") {
      const s = await getSession(st, event);
      if (!s) return json(401, { error: "Sesión no válida." });

      if (method === "GET") {
        const d = await st.get(`data:${s.userId}`, { type: "json" });
        return json(200, d || EMPTY);
      }
      if (method === "PUT") {
        await st.setJSON(`data:${s.userId}`, cleanData(parseBody(event)));
        return json(200, { ok: true });
      }
    }

    if (path === "/ai" && method === "POST") {
      const s = await getSession(st, event);
      if (!s) return json(401, { error: "Sesión no válida." });

      const { message, today, data: ctx } = parseBody(event);
      if (typeof message !== "string" || !message.trim())
        return json(400, { error: "Escribe un mensaje." });
      if (!process.env.GEMINI_API_KEY)
        return json(500, { error: "Falta configurar GEMINI_API_KEY en Netlify." });

      const system = [
        "Eres el asistente de una app de organización de vida. Respondes siempre en español, de forma breve y amable.",
        "Responde SOLO con JSON con esta forma: {\"reply\": \"texto corto\", \"actions\": [...]}.",
        "Acciones permitidas (usa solo estas):",
        "- {\"type\":\"add_event\",\"title\":\"...\",\"date\":\"AAAA-MM-DD\",\"time\":\"HH:MM\" o \"\"}",
        "- {\"type\":\"add_task\",\"title\":\"...\",\"area\":\"Trabajo|Salud|Casa|Personal\",\"date\":\"AAAA-MM-DD\" o \"\",\"priority\":\"alta|media|baja\"}",
        "- {\"type\":\"add_habit\",\"title\":\"...\",\"time\":\"HH:MM\" o \"\",\"end\":\"HH:MM\" o \"\",\"days\":[0-6]}  (0 = domingo, 6 = sábado)",
        "Si la petición es una pregunta (por ejemplo, qué tengo hoy), responde en reply usando los datos y deja actions vacío.",
        "Si la petición pide crear algo, incluye la acción correspondiente y confirma en reply.",
        "Hoy es " + (today || "desconocido") + "."
      ].join("\n");

      const context = "Datos actuales del usuario:\n" + JSON.stringify(cleanData(ctx || {}));

      const r = await fetch(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key=" + process.env.GEMINI_API_KEY,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            systemInstruction: { parts: [{ text: system }] },
            contents: [{ role: "user", parts: [{ text: context + "\n\nPetición: " + message }] }],
            generationConfig: { responseMimeType: "application/json" },
          }),
        }
      );
      const out = await r.json();
      if (!r.ok) return json(502, { error: "Gemini respondió con error: " + ((out.error && out.error.message) || r.status) });

      const text = (out.candidates && out.candidates[0] && out.candidates[0].content.parts[0].text) || "{}";
      let parsed;
      try { parsed = JSON.parse(text); } catch (e) { parsed = { reply: "No pude entender la respuesta. Intenta de nuevo.", actions: [] }; }
      return json(200, {
        reply: String(parsed.reply || "Listo."),
        actions: Array.isArray(parsed.actions) ? parsed.actions : [],
      });
    }

    return json(404, { error: "Ruta no encontrada: " + path });
  } catch (err) {
    console.error(err);
    return json(500, { error: "Error del servidor: " + (err && err.message ? err.message : String(err)) });
  }
};
