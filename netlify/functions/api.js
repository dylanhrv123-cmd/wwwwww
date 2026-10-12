const crypto = require("crypto");
const { getStore } = require("@netlify/blobs");

const st = getStore("organizacion-vida");
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

async function newSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  await st.setJSON(`session:${token}`, {
    userId,
    exp: Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000,
  });
  return { token };
}

async function getSession(event) {
  const header = event.headers.authorization || event.headers.Authorization || "";
  const token = header.replace(/^Bearer\s+/i, "");
  if (!token || token.length < 32) return null;
  const s = await st.get(`session:${token}`, { type: "json" });
  if (!s || s.exp < Date.now()) return null;
  return { token, userId: s.userId };
}

// Sanitiza los datos que llegan del cliente: solo listas conocidas.
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
    // ---- Registro ----
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
      return json(200, await newSession(userId));
    }

    // ---- Inicio de sesión ----
    if (path === "/login" && method === "POST") {
      const { email: rawEmail, password } = parseBody(event);
      const email = String(rawEmail || "").trim().toLowerCase();
      const u = await st.get(`user:${email}`, { type: "json" });
      if (!u || typeof password !== "string" || !checkPassword(password, u.salt, u.hash))
        return json(401, { error: "Correo o contraseña incorrectos." });
      return json(200, await newSession(u.userId));
    }

    // ---- Cerrar sesión ----
    if (path === "/logout" && method === "POST") {
      const s = await getSession(event);
      if (s) await st.delete(`session:${s.token}`);
      return json(200, { ok: true });
    }

    // ---- Datos del usuario ----
    if (path === "/data") {
      const s = await getSession(event);
      if (!s) return json(401, { error: "Sesión no válida." });

      if (method === "GET") {
        const d = await st.get(`data:${s.userId}`, { type: "json" });
        return json(200, d || EMPTY);
      }
      if (method === "PUT") {
        const clean = cleanData(parseBody(event));
        await st.setJSON(`data:${s.userId}`, clean);
        return json(200, { ok: true });
      }
    }

    return json(404, { error: "Ruta no encontrada." });
  } catch (err) {
    console.error(err);
    return json(500, { error: "Error del servidor. Intenta de nuevo." });
  }
};
