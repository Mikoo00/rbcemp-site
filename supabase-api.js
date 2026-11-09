/* ==========================================================================
   Клиент Supabase для сайта РБ №2-ЦЭМП.
   Заменяет бывший серверный api.php: предоставляет функцию rbApi(method, url, body),
   которая возвращает ответы в том же формате, что и PHP-версия.
   Все права проверяются на стороне Supabase (RLS и Edge Functions).
   ========================================================================== */
(function () {
  'use strict';

  const SUPABASE_URL = 'https://zacegyqxbdwbogdarlft.supabase.co';
  // Publishable-ключ предназначен для браузера. Secret-ключ сюда добавлять НЕЛЬЗЯ.
  const SUPABASE_KEY = 'sb_publishable_xuM-q-ufc7Sti7A9UaTXdA_XRPFTACH';
  const LIB_URLS = [
    'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.58.0/dist/umd/supabase.js',
    'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.49.4/dist/umd/supabase.js'
  ];

  const ROLE_RANK = { user: 1, operator: 2, moderator: 3, admin: 4 };

  /* ---------- ошибки ---------- */
  function fail(status, message, field) {
    const e = new Error(message);
    e.status = status;
    e.field = field || null;
    return e;
  }

  /* ---------- загрузка библиотеки и клиента ---------- */
  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = src;
      s.onload = resolve;
      s.onerror = () => reject(new Error('load failed: ' + src));
      document.head.appendChild(s);
    });
  }

  let clientPromise = null;
  function client() {
    if (!clientPromise) {
      clientPromise = (async () => {
        if (!(window.supabase && window.supabase.createClient)) {
          let ok = false;
          for (const u of LIB_URLS) {
            try { await loadScript(u); ok = true; break; } catch (e) { /* пробуем следующий адрес */ }
          }
          if (!ok) throw fail(0, 'Не удалось загрузить библиотеку Supabase. Проверьте подключение к интернету.');
        }
        return window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY, {
          auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: false }
        });
      })();
    }
    return clientPromise;
  }

  /* ---------- валидация (порт из PHP) ---------- */
  const trimStr = v => (typeof v === 'string' ? v.trim() : '');
  function vstr(v, min, max, label, field) {
    const s = trimStr(v);
    if (s.length < min || s.length > max) {
      throw fail(400, `${label}: от ${min} до ${max} символов`, field);
    }
    return s;
  }
  function vopt(v, max, label, field) {
    const s = trimStr(v);
    if (s.length > max) throw fail(400, `${label}: не более ${max} символов`, field);
    return s;
  }
  function vemail(v, required = true) {
    const s = trimStr(v).toLowerCase();
    if (s === '') {
      if (required) throw fail(400, 'Укажите email', 'email');
      return '';
    }
    if (s.length > 200 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(s)) throw fail(400, 'Некорректный email', 'email');
    return s;
  }
  function vphone(v) {
    const raw = vstr(v, 5, 30, 'Телефон', 'phone');
    const norm = raw.replace(/\D/g, '');
    if (norm.length < 10 || norm.length > 15) throw fail(400, 'Некорректный номер телефона', 'phone');
    return { raw, norm };
  }
  function checkPassword(p) {
    if (typeof p !== 'string' || [...p].length < 8) throw fail(400, 'Пароль: минимум 8 символов', 'password');
    if (new TextEncoder().encode(p).length > 72) {
      throw fail(400, 'Пароль слишком длинный (максимум 72 байта, около 36 русских букв)', 'password');
    }
    return p;
  }
  function oneOf(v, list, label) {
    if (!list.includes(v)) throw fail(400, `Недопустимое значение поля «${label}»`);
    return v;
  }
  function toId(v) {
    const n = Number(v);
    if (!Number.isInteger(n) || n < 1) throw fail(400, 'Некорректный идентификатор');
    return n;
  }
  function toUuid(v) {
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(v))) {
      throw fail(400, 'Некорректный идентификатор');
    }
    return String(v);
  }

  /* ---------- обработка ошибок Supabase ---------- */
  function dbFail(error, fallback) {
    if (!error) return null;
    const code = error.code || '';
    const msg = String(error.message || '');
    if (code === '42501' || /row-level security|permission denied/i.test(msg)) {
      return fail(403, 'Недостаточно прав');
    }
    if (code === 'PGRST301' || /JWT/i.test(msg)) return fail(401, 'Требуется вход в аккаунт');
    if (/Failed to fetch|NetworkError|Load failed/i.test(msg)) return fail(0, 'Нет связи с сервером');
    return fail(500, fallback || 'Ошибка сервера');
  }
  function must(res, fallback) {
    if (res.error) throw dbFail(res.error, fallback);
    return res.data;
  }

  /* ---------- текущий пользователь ---------- */
  async function getUser() {
    const sb = await client();
    const { data } = await sb.auth.getSession();
    const session = data && data.session;
    if (!session) return null;
    const res = await sb.from('profiles')
      .select('id,name,email,phone,role,status,created_at,last_login')
      .eq('id', session.user.id).maybeSingle();
    if (res.error || !res.data) return null;
    return res.data;
  }
  async function requireUser(minRole) {
    const u = await getUser();
    if (!u) throw fail(401, 'Требуется вход в аккаунт');
    if (u.status !== 'active') throw fail(403, 'Аккаунт заблокирован. Обратитесь в администрацию.');
    if (minRole && ROLE_RANK[u.role] < ROLE_RANK[minRole]) throw fail(403, 'Недостаточно прав');
    return u;
  }
  async function audit(user, action, details) {
    const sb = await client();
    await sb.from('audit_log').insert({ actor_id: user.id, actor_name: user.name, action, details: details || '' });
  }

  /* ---------- вызов Edge Functions ---------- */
  async function callFn(name, body) {
    const sb = await client();
    const { data, error } = await sb.functions.invoke(name, { body });
    if (error) {
      let status = 500, message = 'Ошибка сервера';
      try {
        if (error.context && typeof error.context.json === 'function') {
          status = error.context.status || status;
          const j = await error.context.json();
          if (j && j.error) message = j.error;
        } else if (error.message) {
          message = /Failed to fetch|NetworkError/i.test(error.message) ? 'Нет связи с сервером' : message;
        }
      } catch (e) { /* оставляем сообщение по умолчанию */ }
      throw fail(status, message);
    }
    return data;
  }

  /* ---------- вспомогательные запросы ---------- */
  async function countOf(table, filter) {
    const sb = await client();
    let q = sb.from(table).select('id', { count: 'exact', head: true });
    if (filter) q = filter(q);
    const { count, error } = await q;
    if (error) throw dbFail(error);
    return count || 0;
  }
  async function otherActiveAdmins(exceptId) {
    return countOf('profiles', q => q.eq('role', 'admin').eq('status', 'active').neq('id', exceptId));
  }

  /* ---------- настройки рекламы ---------- */
  const AD_FIELDS = {
    provider: null,
    adsense_client: /^ca-pub-\d{10,20}$/,
    adsense_slot1: /^\d{6,15}$/,
    adsense_slot2: /^\d{6,15}$/,
    yandex_block1: /^R-A-\d+-\d+$/,
    yandex_block2: /^R-A-\d+-\d+$/
  };
  async function adSettings() {
    const sb = await client();
    const out = {};
    Object.keys(AD_FIELDS).forEach(k => { out[k] = ''; });
    out.provider = 'house';
    const rows = must(await sb.from('settings').select('key,value'));
    rows.forEach(r => { if (Object.prototype.hasOwnProperty.call(AD_FIELDS, r.key)) out[r.key] = r.value; });
    return out;
  }
  function adField(key, v) {
    if (key === 'provider') return oneOf(v, ['off', 'house', 'adsense', 'yandex'], 'Источник рекламы');
    const s = trimStr(v == null ? '' : String(v));
    if (s === '') return '';
    if (!AD_FIELDS[key].test(s)) throw fail(400, `Неверный формат поля «${key}»`);
    return s;
  }
  function safeUrl(v) {
    const s = vstr(v, 2, 500, 'Ссылка', 'url');
    if (/^#[a-z]{3,20}$/.test(s)) return s;
    let u;
    try { u = new URL(s); } catch (e) { u = null; }
    if (!u || !['http:', 'https:'].includes(u.protocol) || !u.hostname) {
      throw fail(400, 'Ссылка должна начинаться с http:// или https://', 'url');
    }
    return s;
  }

  /* ---------- маршруты ---------- */
  const routes = [];
  const route = (method, pattern, fn) => {
    const names = [];
    const re = new RegExp('^' + pattern.replace(/:(\w+)/g, (_, n) => { names.push(n); return '([^/]+)'; }) + '$');
    routes.push({ method, re, names, fn });
  };

  /* ===== авторизация ===== */
  route('GET', '/health', async () => ({ ok: true, backend: 'supabase' }));

  route('GET', '/auth/me', async () => {
    const u = await getUser();
    if (u && u.status !== 'active') {
      const sb = await client();
      await sb.auth.signOut();
      return { user: null };
    }
    return { user: u };
  });

  route('POST', '/auth/register', async (c) => {
    const b = c.body;
    const name = vstr(b.name, 3, 100, 'ФИО', 'name');
    const mail = vemail(b.email);
    const ph = vphone(b.phone);
    const pwd = checkPassword(b.password);
    const sb = await client();
    const { data, error } = await sb.auth.signUp({
      email: mail, password: pwd, options: { data: { name, phone: ph.raw } }
    });
    if (error) {
      const m = String(error.message || '');
      if (/already registered|already been registered/i.test(m)) throw fail(409, 'Пользователь с таким email уже существует', 'email');
      if (/Database error/i.test(m)) throw fail(409, 'Пользователь с таким телефоном уже существует', 'phone');
      if (/password/i.test(m)) throw fail(400, 'Пароль слишком простой. Используйте буквы разного регистра и цифры.', 'password');
      if (/rate limit|too many/i.test(m)) throw fail(429, 'Слишком много попыток. Попробуйте позже.');
      throw fail(400, 'Не удалось зарегистрироваться');
    }
    // Supabase не сообщает об ошибке, если email уже занят и подтверждение почты включено
    if (data.user && Array.isArray(data.user.identities) && data.user.identities.length === 0) {
      throw fail(409, 'Пользователь с таким email уже существует', 'email');
    }
    let session = data.session;
    if (!session) {
      const r = await sb.auth.signInWithPassword({ email: mail, password: pwd });
      session = r.data && r.data.session;
      if (!session) throw fail(400, 'Аккаунт создан. Подтвердите email по ссылке из письма, затем войдите.');
    }
    const u = await getUser();
    if (!u) throw fail(500, 'Аккаунт создан, но профиль не найден. Попробуйте войти.');
    return { user: u };
  });

  route('POST', '/auth/login', async (c) => {
    const id = vstr(c.body.id, 3, 120, 'Email', 'id').toLowerCase();
    const pwd = typeof c.body.password === 'string' ? c.body.password : '';
    if (!id.includes('@')) throw fail(400, 'Для входа используйте email, указанный при регистрации', 'id');
    const sb = await client();
    const { error } = await sb.auth.signInWithPassword({ email: id, password: pwd });
    if (error) {
      if (/not confirmed/i.test(error.message || '')) throw fail(403, 'Подтвердите email по ссылке из письма');
      if (/rate limit|too many/i.test(error.message || '')) throw fail(429, 'Слишком много попыток. Попробуйте позже.');
      throw fail(401, 'Неверный email или пароль');
    }
    const u = await getUser();
    if (!u || u.status !== 'active') {
      await sb.auth.signOut();
      throw fail(403, 'Аккаунт заблокирован. Обратитесь в администрацию.');
    }
    const now = new Date().toISOString();
    await sb.from('profiles').update({ last_login: now }).eq('id', u.id);
    u.last_login = now;
    return { user: u };
  });

  route('POST', '/auth/logout', async () => {
    const sb = await client();
    await sb.auth.signOut();
    return { ok: true };
  });

  route('POST', '/auth/password', async (c) => {
    const u = await requireUser();
    const current = typeof c.body.current === 'string' ? c.body.current : '';
    const sb = await client();
    const chk = await sb.auth.signInWithPassword({ email: u.email, password: current });
    if (chk.error) throw fail(400, 'Текущий пароль указан неверно', 'current');
    const next = checkPassword(c.body.next);
    const { error } = await sb.auth.updateUser({ password: next });
    if (error) {
      if (/same|different/i.test(error.message || '')) throw fail(400, 'Новый пароль должен отличаться от текущего', 'password');
      throw fail(400, 'Не удалось изменить пароль', 'password');
    }
    return { ok: true };
  });

  /* ===== публичные данные и формы ===== */
  route('GET', '/reviews', async () => {
    const sb = await client();
    const rows = must(await sb.from('reviews').select('id,name,rating,text,created_at')
      .eq('status', 'approved').order('created_at', { ascending: false }).limit(30));
    return { reviews: rows };
  });

  route('POST', '/reviews', async (c) => {
    const u = await requireUser('user');
    const b = c.body;
    let name = vopt(b.name, 100, 'Имя', 'name');
    if (name === '') name = u.name;
    const rating = Number(b.rating);
    if (!Number.isInteger(rating) || rating < 1 || rating > 5) throw fail(400, 'Оценка от 1 до 5', 'rating');
    const text = vstr(b.text, 10, 2000, 'Отзыв', 'text');
    const status = ROLE_RANK[u.role] >= ROLE_RANK.moderator ? 'approved' : 'pending';
    const sb = await client();
    const row = must(await sb.from('reviews')
      .insert({ user_id: u.id, name, rating, text, status }).select('id').single(), 'Не удалось отправить отзыв');
    return { id: row.id, status };
  });

  route('POST', '/appointments', async (c) => {
    const b = c.body;
    const name = vstr(b.name, 2, 100, 'Имя', 'name');
    const ph = vphone(b.phone);
    const mail = vemail(b.email, false);
    const specialist = vstr(b.specialist, 2, 60, 'Специалист', 'specialist');
    const date = vopt(b.date, 10, 'Дата', 'date');
    if (date !== '') {
      const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date);
      const d = m ? new Date(Date.UTC(+m[1], +m[2] - 1, +m[3])) : null;
      if (!d || d.toISOString().slice(0, 10) !== date) throw fail(400, 'Некорректная дата', 'date');
      const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
      if (date < yesterday) throw fail(400, 'Дата не может быть в прошлом', 'date');
    }
    const u = await getUser();
    const sb = await client();
    const { error } = await sb.from('appointments').insert({
      user_id: u && u.status === 'active' ? u.id : null,
      name, phone: ph.raw, email: mail || null, specialist, date: date === '' ? null : date
    });
    if (error) throw dbFail(error, 'Не удалось отправить запись');
    return { ok: true };
  });

  route('POST', '/resumes', async (c) => {
    const b = c.body;
    const fio = vstr(b.fio, 3, 100, 'ФИО', 'fio');
    const ph = vphone(b.phone);
    const mail = vemail(b.email);
    const position = vstr(b.position, 2, 80, 'Должность', 'position');
    const experience = vopt(b.experience, 3000, 'Опыт работы', 'experience');
    const u = await getUser();
    const sb = await client();
    const { error } = await sb.from('resumes').insert({
      user_id: u && u.status === 'active' ? u.id : null,
      fio, phone: ph.raw, email: mail, position, experience
    });
    if (error) throw dbFail(error, 'Не удалось отправить резюме');
    return { ok: true };
  });

  /* ===== личный кабинет ===== */
  route('GET', '/me/overview', async () => {
    const u = await requireUser();
    const sb = await client();
    const appointments = must(await sb.from('appointments').select('id,specialist,date,status,created_at')
      .eq('user_id', u.id).order('created_at', { ascending: false }).limit(50));
    const reviews = must(await sb.from('reviews').select('id,rating,text,status,created_at')
      .eq('user_id', u.id).order('created_at', { ascending: false }).limit(50));
    return { appointments, reviews };
  });

  route('POST', '/appointments/:id/cancel', async (c) => {
    const u = await requireUser();
    const id = toId(c.params.id);
    const sb = await client();
    const rows = must(await sb.from('appointments').update({ status: 'cancelled' })
      .eq('id', id).eq('user_id', u.id).in('status', ['new', 'confirmed']).select('id'));
    if (!rows || rows.length === 0) throw fail(400, 'Эту запись нельзя отменить или она не найдена');
    return { ok: true };
  });

  /* ===== персонал: модератор и выше ===== */
  route('GET', '/admin/stats', async () => {
    const u = await requireUser('moderator');
    const stats = {
      appointments: await countOf('appointments'),
      newAppointments: await countOf('appointments', q => q.eq('status', 'new')),
      reviews: await countOf('reviews'),
      pendingReviews: await countOf('reviews', q => q.eq('status', 'pending'))
    };
    if (u.role === 'admin') {
      stats.users = await countOf('profiles');
      stats.resumes = await countOf('resumes');
      stats.newResumes = await countOf('resumes', q => q.eq('status', 'new'));
    }
    return { stats };
  });

  route('GET', '/admin/appointments', async () => {
    await requireUser('moderator');
    const sb = await client();
    const rank = { new: 0, confirmed: 1 };
    const rows = must(await sb.from('appointments').select('*').order('created_at', { ascending: false }).limit(300));
    rows.sort((a, b) => (rank[a.status] ?? 2) - (rank[b.status] ?? 2));
    return { items: rows };
  });

  route('PATCH', '/admin/appointments/:id', async (c) => {
    const u = await requireUser('moderator');
    const id = toId(c.params.id);
    const status = oneOf(c.body.status, ['new', 'confirmed', 'done', 'cancelled'], 'Статус');
    const sb = await client();
    const rows = must(await sb.from('appointments').update({ status }).eq('id', id).select('id'));
    if (!rows.length) throw fail(404, 'Запись не найдена');
    await audit(u, 'appointment.status', `запись #${id} → ${status}`);
    return { ok: true };
  });

  route('GET', '/admin/reviews', async () => {
    await requireUser('moderator');
    const sb = await client();
    const rows = must(await sb.from('reviews').select('*').order('created_at', { ascending: false }).limit(300));
    rows.sort((a, b) => (a.status === 'pending' ? 0 : 1) - (b.status === 'pending' ? 0 : 1));
    return { items: rows };
  });

  route('PATCH', '/admin/reviews/:id', async (c) => {
    const u = await requireUser('moderator');
    const id = toId(c.params.id);
    const status = oneOf(c.body.status, ['pending', 'approved', 'rejected'], 'Статус');
    const sb = await client();
    const rows = must(await sb.from('reviews').update({ status }).eq('id', id).select('id'));
    if (!rows.length) throw fail(404, 'Отзыв не найден');
    await audit(u, 'review.status', `отзыв #${id} → ${status}`);
    return { ok: true };
  });

  route('DELETE', '/admin/reviews/:id', async (c) => {
    const u = await requireUser('moderator');
    const id = toId(c.params.id);
    const sb = await client();
    const rows = must(await sb.from('reviews').delete().eq('id', id).select('id'));
    if (!rows.length) throw fail(404, 'Отзыв не найден');
    await audit(u, 'review.delete', `отзыв #${id}`);
    return { ok: true };
  });

  /* ===== администратор ===== */
  route('GET', '/admin/resumes', async () => {
    await requireUser('admin');
    const sb = await client();
    return { items: must(await sb.from('resumes').select('*').order('created_at', { ascending: false }).limit(300)) };
  });

  route('PATCH', '/admin/resumes/:id', async (c) => {
    await requireUser('admin');
    const id = toId(c.params.id);
    const status = oneOf(c.body.status, ['new', 'viewed'], 'Статус');
    const sb = await client();
    const rows = must(await sb.from('resumes').update({ status }).eq('id', id).select('id'));
    if (!rows.length) throw fail(404, 'Резюме не найдено');
    return { ok: true };
  });

  route('DELETE', '/admin/resumes/:id', async (c) => {
    const u = await requireUser('admin');
    const id = toId(c.params.id);
    const sb = await client();
    const rows = must(await sb.from('resumes').delete().eq('id', id).select('id'));
    if (!rows.length) throw fail(404, 'Резюме не найдено');
    await audit(u, 'resume.delete', `резюме #${id}`);
    return { ok: true };
  });

  route('GET', '/admin/users', async () => {
    await requireUser('admin');
    const sb = await client();
    const rank = { admin: 0, moderator: 1 };
    const rows = must(await sb.from('profiles')
      .select('id,name,email,phone,role,status,created_at,last_login').order('created_at', { ascending: false }));
    rows.sort((a, b) => (rank[a.role] ?? 2) - (rank[b.role] ?? 2));
    return { items: rows };
  });

  route('PATCH', '/admin/users/:id', async (c) => {
    const me = await requireUser('admin');
    const b = c.body;
    const id = toUuid(c.params.id);
    const sb = await client();
    const target = must(await sb.from('profiles').select('*').eq('id', id).maybeSingle());
    if (!target) throw fail(404, 'Пользователь не найден');
    const changes = [];
    const patch = {};
    if (b.role !== undefined && b.role !== null) {
      const role = oneOf(b.role, ['user', 'operator', 'moderator', 'admin'], 'Роль');
      if (id === me.id && role !== 'admin') throw fail(400, 'Нельзя снять роль администратора с самого себя');
      if (target.role === 'admin' && role !== 'admin' && (await otherActiveAdmins(id)) < 1) {
        throw fail(400, 'Нельзя убрать последнего администратора');
      }
      if (role !== target.role) { patch.role = role; changes.push(`роль ${target.role} → ${role}`); }
    }
    if (b.status !== undefined && b.status !== null) {
      const status = oneOf(b.status, ['active', 'blocked'], 'Статус');
      if (id === me.id && status !== 'active') throw fail(400, 'Нельзя заблокировать самого себя');
      if (target.role === 'admin' && status === 'blocked' && (await otherActiveAdmins(id)) < 1) {
        throw fail(400, 'Нельзя заблокировать последнего администратора');
      }
      if (status !== target.status) { patch.status = status; changes.push(`статус ${target.status} → ${status}`); }
    }
    if (changes.length) {
      const rows = must(await sb.from('profiles').update(patch).eq('id', id).select('id'));
      if (!rows.length) throw fail(404, 'Пользователь не найден');
      await audit(me, 'user.update', `${target.email}: ${changes.join(', ')}`);
    }
    return { ok: true };
  });

  route('POST', '/admin/users/:id/reset-password', async (c) => {
    await requireUser('admin');
    return callFn('admin-actions', { action: 'reset_password', user_id: toUuid(c.params.id) });
  });

  route('DELETE', '/admin/users/:id', async (c) => {
    await requireUser('admin');
    return callFn('admin-actions', { action: 'delete_user', user_id: toUuid(c.params.id) });
  });

  route('GET', '/admin/audit', async () => {
    await requireUser('admin');
    const sb = await client();
    return { items: must(await sb.from('audit_log').select('*').order('id', { ascending: false }).limit(100)) };
  });

  /* ===== реклама ===== */
  route('GET', '/ads', async () => {
    const sb = await client();
    const house = must(await sb.from('house_ads').select('id,title,text,url,slot')
      .eq('active', true).order('id', { ascending: false }).limit(20));
    return { ads: await adSettings(), house };
  });

  route('GET', '/admin/ads', async () => {
    await requireUser('admin');
    const sb = await client();
    const house = must(await sb.from('house_ads').select('*').order('id', { ascending: false }));
    return { settings: await adSettings(), house };
  });

  route('PUT', '/admin/ads', async (c) => {
    const u = await requireUser('admin');
    const clean = {};
    Object.keys(AD_FIELDS).forEach(k => {
      if (Object.prototype.hasOwnProperty.call(c.body, k)) clean[k] = adField(k, c.body[k]);
    });
    const eff = Object.assign(await adSettings(), clean);
    if (eff.provider === 'adsense' && !(eff.adsense_client !== '' && (eff.adsense_slot1 !== '' || eff.adsense_slot2 !== ''))) {
      throw fail(400, 'Для AdSense укажите client ID и хотя бы один slot');
    }
    if (eff.provider === 'yandex' && eff.yandex_block1 === '' && eff.yandex_block2 === '') {
      throw fail(400, 'Для Яндекса укажите хотя бы один blockId');
    }
    const rows = Object.keys(clean).map(k => ({ key: k, value: clean[k] }));
    if (rows.length) {
      const sb = await client();
      must(await sb.from('settings').upsert(rows, { onConflict: 'key' }), 'Не удалось сохранить настройки');
    }
    await audit(u, 'ads.settings', 'источник: ' + eff.provider);
    return { ok: true };
  });

  route('POST', '/admin/ads/house', async (c) => {
    const u = await requireUser('admin');
    const b = c.body;
    const title = vstr(b.title, 3, 80, 'Заголовок', 'title');
    const text = vstr(b.text, 3, 200, 'Текст', 'text');
    const url = safeUrl(b.url);
    let slot = Number(b.slot || 0);
    if (![0, 1, 2].includes(slot)) slot = 0;
    const sb = await client();
    const row = must(await sb.from('house_ads').insert({ title, text, url, slot, active: true }).select('id').single());
    await audit(u, 'ads.house.create', title);
    return { id: row.id };
  });

  route('PATCH', '/admin/ads/house/:id', async (c) => {
    const u = await requireUser('admin');
    const id = toId(c.params.id);
    const v = c.body.active;
    const active = v === true || v === 1 || v === '1' || v === 'true';
    const sb = await client();
    const rows = must(await sb.from('house_ads').update({ active }).eq('id', id).select('id'));
    if (!rows.length) throw fail(404, 'Баннер не найден');
    await audit(u, 'ads.house.toggle', `#${id} → ${active ? 'вкл' : 'выкл'}`);
    return { ok: true };
  });

  route('DELETE', '/admin/ads/house/:id', async (c) => {
    const u = await requireUser('admin');
    const id = toId(c.params.id);
    const sb = await client();
    const rows = must(await sb.from('house_ads').delete().eq('id', id).select('id'));
    if (!rows.length) throw fail(404, 'Баннер не найден');
    await audit(u, 'ads.house.delete', `#${id}`);
    return { ok: true };
  });

  /* ===== поддержка ===== */
  async function ticketMessages(sb, id) {
    return must(await sb.from('support_messages').select('id,sender_role,message,created_at')
      .eq('ticket_id', id).order('id', { ascending: true }));
  }

  route('POST', '/support/tickets', async (c) => {
    const b = c.body;
    const message = vstr(b.message, 2, 3000, 'Сообщение', 'message');
    const subject = vopt(b.subject, 120, 'Тема') || 'Обращение в поддержку';
    const u = await getUser();
    if (u && u.status === 'active') {
      const sb = await client();
      const t = must(await sb.from('support_tickets').insert({ user_id: u.id, subject }).select('id').single(),
        'Не удалось создать обращение');
      must(await sb.from('support_messages').insert({ ticket_id: t.id, sender_id: u.id, sender_role: u.role, message }));
      return { ticket_id: t.id };
    }
    return callFn('guest-support', {
      action: 'create', message, subject,
      guest_token: b.guest_token, name: b.name, email: b.email
    });
  });

  route('GET', '/support/tickets/:id', async (c) => {
    const id = toId(c.params.id);
    const token = c.query.get('token') || '';
    const u = await getUser();
    if (u && u.status === 'active') {
      const sb = await client();
      const t = must(await sb.from('support_tickets').select('id,subject,status,created_at,updated_at')
        .eq('id', id).maybeSingle());
      if (t) return { ticket: Object.assign({}, t, { messages: await ticketMessages(sb, id) }) };
      if (!token) throw fail(404, 'Обращение не найдено');
    }
    return callFn('guest-support', { action: 'get', ticket_id: id, guest_token: token });
  });

  route('POST', '/support/tickets/:id/messages', async (c) => {
    const id = toId(c.params.id);
    const u = await getUser();
    if (u && u.status === 'active') {
      const sb = await client();
      const t = must(await sb.from('support_tickets').select('id,status').eq('id', id).maybeSingle());
      if (t) {
        if (t.status === 'closed') throw fail(400, 'Обращение закрыто');
        const message = vstr(c.body.message, 1, 3000, 'Сообщение');
        must(await sb.from('support_messages').insert({ ticket_id: id, sender_id: u.id, sender_role: u.role, message }));
        return { ok: true };
      }
    }
    vstr(c.body.message, 1, 3000, 'Сообщение');
    return callFn('guest-support', { action: 'reply', ticket_id: id, guest_token: c.body.guest_token, message: c.body.message });
  });

  /* ===== оператор поддержки ===== */
  route('GET', '/operator/tickets', async () => {
    await requireUser('operator');
    const sb = await client();
    const tickets = must(await sb.from('support_tickets').select('*').order('updated_at', { ascending: false }).limit(300));
    const ids = tickets.map(t => t.id);
    const last = {}, count = {};
    if (ids.length) {
      const msgs = must(await sb.from('support_messages').select('id,ticket_id,message')
        .in('ticket_id', ids).order('id', { ascending: false }).limit(5000));
      msgs.forEach(m => {
        count[m.ticket_id] = (count[m.ticket_id] || 0) + 1;
        if (!(m.ticket_id in last)) last[m.ticket_id] = m.message;
      });
    }
    tickets.forEach(t => { t.last_message = last[t.id] || ''; t.message_count = count[t.id] || 0; delete t.guest_token; });
    tickets.sort((a, b) => (a.status === 'open' ? 0 : 1) - (b.status === 'open' ? 0 : 1));
    return { items: tickets };
  });

  route('GET', '/operator/tickets/:id', async (c) => {
    await requireUser('operator');
    const id = toId(c.params.id);
    const sb = await client();
    const t = must(await sb.from('support_tickets').select('*').eq('id', id).maybeSingle());
    if (!t) throw fail(404, 'Обращение не найдено');
    delete t.guest_token;
    return { ticket: t, messages: await ticketMessages(sb, id) };
  });

  route('POST', '/operator/tickets/:id/messages', async (c) => {
    const u = await requireUser('operator');
    const id = toId(c.params.id);
    const sb = await client();
    const t = must(await sb.from('support_tickets').select('id,status').eq('id', id).maybeSingle());
    if (!t) throw fail(404, 'Обращение не найдено');
    if (t.status === 'closed') throw fail(400, 'Обращение закрыто');
    const message = vstr(c.body.message, 1, 3000, 'Сообщение');
    must(await sb.from('support_messages').insert({ ticket_id: id, sender_id: u.id, sender_role: 'operator', message }));
    await sb.from('support_tickets').update({ assigned_to: u.id }).eq('id', id);
    return { ok: true };
  });

  route('PATCH', '/operator/tickets/:id', async (c) => {
    const u = await requireUser('operator');
    const id = toId(c.params.id);
    const status = oneOf(c.body.status, ['open', 'closed'], 'Статус');
    const sb = await client();
    const rows = must(await sb.from('support_tickets').update({ status, updated_at: new Date().toISOString() })
      .eq('id', id).select('id'));
    if (!rows.length) throw fail(404, 'Обращение не найдено');
    await audit(u, 'support.ticket.status', `обращение #${id} → ${status}`);
    return { ok: true };
  });

  /* ---------- диспетчер ---------- */
  async function rbApi(method, url, body) {
    method = String(method || 'GET').toUpperCase();
    const qi = String(url).indexOf('?');
    const path = '/' + (qi === -1 ? String(url) : String(url).slice(0, qi)).replace(/^\/+|\/+$/g, '');
    const query = new URLSearchParams(qi === -1 ? '' : String(url).slice(qi + 1));
    for (const r of routes) {
      if (r.method !== method) continue;
      const m = r.re.exec(path);
      if (!m) continue;
      const params = {};
      r.names.forEach((n, i) => { params[n] = decodeURIComponent(m[i + 1]); });
      try {
        return await r.fn({ params, body: body || {}, query });
      } catch (e) {
        if (e && typeof e.status === 'number') throw e;
        console.error('[rbcemp]', e);
        const msg = String((e && e.message) || '');
        throw fail(/fetch|network/i.test(msg) ? 0 : 500, /fetch|network/i.test(msg) ? 'Нет связи с сервером' : 'Внутренняя ошибка сервера');
      }
    }
    throw fail(404, 'Не найдено');
  }

  window.rbApi = rbApi;
})();
