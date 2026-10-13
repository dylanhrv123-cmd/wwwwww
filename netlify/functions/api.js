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

const PROFILE_EMPTY = { name: "", accent: "#c9b8ff", photo: "", motto: "", birthday: "", role: "", goals: [], goalsMonth: "", share: { photo: true, stats: true } };
const CODE_CHARS = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // sin caracteres confusos (0/O, 1/I)

// Crea un código único tipo OV-7K3P y lo reserva para este usuario
async function uniqueCode(st, userId) {
  for (let tries = 0; tries < 10; tries++) {
    let c = "";
    for (let i = 0; i < 4; i++) c += CODE_CHARS[crypto.randomInt(CODE_CHARS.length)];
    const code = "OV-" + c;
    if (!(await st.get(`code:${code}`, { type: "json" }))) {
      await st.setJSON(`code:${code}`, { userId });
      return code;
    }
  }
  throw new Error("No se pudo generar un código de amigo.");
}

// Solo acepta los campos del perfil con su tipo y tamaño; el código no se cambia desde el cliente
function cleanProfile(input) {
  const i = input || {};
  const s = (v, max) => (typeof v === "string" ? v.slice(0, max) : "");
  return {
    name: s(i.name, 30),
    accent: /^#[0-9a-fA-F]{6}$/.test(i.accent) ? i.accent : PROFILE_EMPTY.accent,
    photo: typeof i.photo === "string" && i.photo.startsWith("data:image/") && i.photo.length < 300000 ? i.photo : "",
    motto: s(i.motto, 80),
    birthday: /^\d{4}-\d{2}-\d{2}$/.test(i.birthday) ? i.birthday : "",
    role: ["estudiante", "trabajo", "casa"].includes(i.role) ? i.role : "",
    goals: Array.isArray(i.goals)
      ? i.goals.slice(0, 10).map(g => ({
          title: s(g && g.title, 40),
          progress: Math.min(100, Math.max(0, Number(g && g.progress) || 0))
        }))
      : [],
    goalsMonth: /^\d{4}-\d{2}$/.test(i.goalsMonth) ? i.goalsMonth : "",
    share: { photo: !(i.share && i.share.photo === false), stats: !(i.share && i.share.stats === false) },
  };
}

function cleanStats(s) {
  const n = v => (Number.isFinite(Number(v)) ? Math.max(0, Math.floor(Number(v))) : 0);
  return { longest: n(s.longest), habitsMonth: n(s.habitsMonth), tasksDone: n(s.tasksDone), activeDays: n(s.activeDays) };
}

// Rutas de amigos: solicitudes, amistades y estadísticas compartidas
async function friendsRoute(st, me, path, method, event) {
  const body = parseBody(event);
  const list = async k => (await st.get(k, { type: "json" })) || [];
  const reqKey = id => `requests:${id}`;   // solicitudes recibidas: [{fromId, at}]
  const outKey = id => `outgoing:${id}`;   // solicitudes enviadas: [id]
  const frKey = id => `friends:${id}`;     // amigos: [id]
  const cardOf = async id => {
    const p = (await st.get(`profile:${id}`, { type: "json" })) || PROFILE_EMPTY;
    const sharePhoto = !(p.share && p.share.photo === false);
    return { id, name: p.name || "", code: p.code || "", photo: sharePhoto ? (p.photo || "") : "" };
  };

  if (path === "/friends" && method === "GET") {
    const friends = await list(frKey(me));
    const reqs = await list(reqKey(me));
    const out = await list(outKey(me));
    return json(200, {
      friends: await Promise.all(friends.map(cardOf)),
      requests: await Promise.all(reqs.map(r => cardOf(r.fromId))),
      outgoing: await Promise.all(out.map(cardOf)),
    });
  }

  if (path === "/friends/request" && method === "POST") {
    const raw = typeof body.target === "string" ? body.target.trim() : "";
    const isCode = /^OV-/i.test(raw);
    const email = raw.toLowerCase();
    if (!isCode && !validEmail(email)) return json(400, { error: "Escribe un código (OV-XXXX) o un correo válido." });

    let targetId = null;
    if (isCode) {
      const rec = await st.get(`code:${raw.toUpperCase()}`, { type: "json" });
      if (!rec) return json(404, { error: "No existe ningún usuario con ese código." });
      targetId = rec.userId;
    } else {
      const u = await st.get(`user:${email}`, { type: "json" });
      targetId = u ? u.userId : null;
    }

    // Con correo, la respuesta es igual exista o no la cuenta, para no revelar qué correos están registrados
    const neutral = "Si existe una cuenta con ese correo, se envió la solicitud.";
    if (!targetId) return json(200, { message: isCode ? "" : neutral });
    if (targetId === me) return json(400, { error: "No puedes agregarte a ti mismo." });

    const friends = await list(frKey(me));
    const out = await list(outKey(me));
    const inc = await list(reqKey(me));
    if (!friends.includes(targetId) && !out.includes(targetId) && !inc.some(r => r.fromId === targetId)) {
      const theirs = await list(reqKey(targetId));
      theirs.push({ fromId: me, at: Date.now() });
      await st.setJSON(reqKey(targetId), theirs);
      out.push(targetId);
      await st.setJSON(outKey(me), out);
    }
    if (!isCode) return json(200, { message: neutral });
    return json(200, { message: "Solicitud enviada." });
  }

  if (path === "/friends/accept" && method === "POST") {
    const from = body.fromId;
    const inc = await list(reqKey(me));
    if (!inc.some(r => r.fromId === from)) return json(404, { error: "Esa solicitud ya no existe." });
    await st.setJSON(reqKey(me), inc.filter(r => r.fromId !== from));
    const mine = await list(frKey(me));
    if (!mine.includes(from)) { mine.push(from); await st.setJSON(frKey(me), mine); }
    const theirs = await list(frKey(from));
    if (!theirs.includes(me)) { theirs.push(me); await st.setJSON(frKey(from), theirs); }
    await st.setJSON(outKey(from), (await list(outKey(from))).filter(id => id !== me));
    return json(200, { ok: true });
  }

  if (path === "/friends/decline" && method === "POST") {
    const from = body.fromId;
    await st.setJSON(reqKey(me), (await list(reqKey(me))).filter(r => r.fromId !== from));
    await st.setJSON(outKey(from), (await list(outKey(from))).filter(id => id !== me));
    return json(200, { ok: true });
  }

  if (path === "/friends/cancel" && method === "POST") {
    const to = body.toId;
    await st.setJSON(outKey(me), (await list(outKey(me))).filter(id => id !== to));
    await st.setJSON(reqKey(to), (await list(reqKey(to))).filter(r => r.fromId !== me));
    return json(200, { ok: true });
  }

  if (path === "/friends/remove" && method === "POST") {
    const other = body.friendId;
    await st.setJSON(frKey(me), (await list(frKey(me))).filter(id => id !== other));
    await st.setJSON(frKey(other), (await list(frKey(other))).filter(id => id !== me));
    return json(200, { ok: true });
  }

  if (path === "/friend-stats" && method === "GET") {
    const id = (event.queryStringParameters || {}).id;
    const mine = await list(frKey(me));
    if (!id || !mine.includes(id)) return json(403, { error: "Solo puedes ver las estadísticas de tus amigos." });
    const p = (await st.get(`profile:${id}`, { type: "json" })) || PROFILE_EMPTY;
    if (p.share && p.share.stats === false) return json(200, { card: await cardOf(id), hidden: true });
    const stats = (await st.get(`stats:${id}`, { type: "json" })) || null;
    return json(200, { card: await cardOf(id), stats, hidden: false });
  }

  return json(404, { error: "Ruta de amigos no encontrada." });
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
        const body = parseBody(event);
        await st.setJSON(`data:${s.userId}`, cleanData(body));
        if (body.stats && typeof body.stats === "object") await st.setJSON(`stats:${s.userId}`, cleanStats(body.stats));
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

    if (path === "/profile") {
      const s = await getSession(st, event);
      if (!s) return json(401, { error: "Sesión no válida." });
      const key = `profile:${s.userId}`;
      let rec = await st.get(key, { type: "json" });

      if (method === "GET") {
        if (!rec) {
          rec = { ...PROFILE_EMPTY, code: await uniqueCode(st, s.userId) };
          await st.setJSON(key, rec);
        }
        return json(200, rec);
      }
      if (method === "PUT") {
        if (!rec) rec = { code: await uniqueCode(st, s.userId) };
        const next = { ...cleanProfile(parseBody(event)), code: rec.code };
        await st.setJSON(key, next);
        return json(200, next);
      }
    }

    if (path === "/friends" || path.startsWith("/friends/") || path === "/friend-stats") {
      const s = await getSession(st, event);
      if (!s) return json(401, { error: "Sesión no válida." });
      return friendsRoute(st, s.userId, path, method, event);
    }

    return json(404, { error: "Ruta no encontrada: " + path });
  } catch (err) {
    console.error(err);
    return json(500, { error: "Error del servidor: " + (err && err.message ? err.message : String(err)) });
  }
};
