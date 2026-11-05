<?php
/*
  API сайта. Адреса вида: api.php?r=/auth/login
  (без mod_rewrite, поэтому работает в любой папке и на любом хостинге).
*/
require __DIR__ . '/../app/bootstrap.php';

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: same-origin');

/* ============ МАРШРУТИЗАТОР ============ */

$GLOBALS['ROUTES'] = [];

function route(string $method, string $pattern, ?string $minRole, callable $fn): void
{
    $re = '#^' . preg_replace('#:(\w+)#', '(?P<$1>[^/]+)', $pattern) . '$#';
    $GLOBALS['ROUTES'][] = [$method, $re, $minRole, $fn];
}

function check_csrf(): void
{
    $ct = $_SERVER['CONTENT_TYPE'] ?? ($_SERVER['HTTP_CONTENT_TYPE'] ?? '');
    if (stripos($ct, 'application/json') === false) {
        throw new HttpError(415, 'Ожидается application/json');
    }
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin !== '') {
        $host = (string) parse_url($origin, PHP_URL_HOST);
        $port = parse_url($origin, PHP_URL_PORT);
        $originHost = $host . ($port ? ':' . $port : '');
        $myHost = $_SERVER['HTTP_HOST'] ?? '';
        $allowed = cfg('allowed_origins', []);
        if (strcasecmp($originHost, $myHost) !== 0 && !in_array($origin, $allowed, true)) {
            throw new HttpError(403, 'Запрещённый источник запроса');
        }
    }
}

function dispatch(string $method, string $path): void
{
    $mutating = !in_array($method, ['GET', 'HEAD'], true);
    if ($mutating) {
        check_csrf();
    }
    foreach ($GLOBALS['ROUTES'] as [$m, $re, $minRole, $fn]) {
        if ($m !== $method || !preg_match($re, $path, $mm)) {
            continue;
        }
        $user = current_user();
        if ($minRole !== null) {
            if ($user === null) {
                throw new HttpError(401, 'Требуется вход в аккаунт');
            }
            if (ROLE_RANK[$user['role']] < ROLE_RANK[$minRole]) {
                throw new HttpError(403, 'Недостаточно прав');
            }
        }
        $params = [];
        foreach ($mm as $k => $v) {
            if (is_string($k)) {
                $params[$k] = $v;
            }
        }
        $fn([
            'params' => $params,
            'body' => $mutating ? read_body() : [],
            'user' => $user,
            'ip' => client_ip(),
        ]);
        return;
    }
    throw new HttpError(404, 'Не найдено');
}

/* ============ АВТОРИЗАЦИЯ ============ */

route('GET', '/health', null, function () {
    json_out(200, [
        'ok' => true,
        'php' => PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION,
        'pdo_sqlite' => extension_loaded('pdo_sqlite'),
        'mbstring' => extension_loaded('mbstring'),
    ]);
});

route('GET', '/auth/me', null, function ($c) {
    json_out(200, ['user' => public_user($c['user'])]);
});

route('POST', '/auth/register', null, function ($c) {
    $b = $c['body'];
    limit('reg:' . $c['ip'], 10, 3600);
    $name = vstr($b['name'] ?? null, 3, 100, 'ФИО', 'name');
    $mail = vemail($b['email'] ?? null);
    $ph = vphone($b['phone'] ?? null);
    $pwd = check_password($b['password'] ?? null);
    if (row('SELECT 1 FROM users WHERE email = ?', [$mail]) !== null) {
        throw new HttpError(409, 'Пользователь с таким email уже существует', 'email');
    }
    if (row('SELECT 1 FROM users WHERE phone_norm = ?', [$ph['norm']]) !== null) {
        throw new HttpError(409, 'Пользователь с таким телефоном уже существует', 'phone');
    }
    q("INSERT INTO users (name, email, phone, phone_norm, pass_hash, role, status, created_at, last_login)
       VALUES (?, ?, ?, ?, ?, 'user', 'active', ?, ?)",
        [$name, $mail, $ph['raw'], $ph['norm'], hash_pw($pwd), now(), now()]);
    $id = last_id();
    create_session($id);
    json_out(201, ['user' => public_user(row('SELECT * FROM users WHERE id = ?', [$id]))]);
});

route('POST', '/auth/login', null, function ($c) {
    $b = $c['body'];
    $id = strtolower(vstr($b['id'] ?? null, 3, 120, 'Email или телефон', 'id'));
    $pwd = is_string($b['password'] ?? null) ? $b['password'] : '';
    limit('login:' . $c['ip'], 20, 900);
    limit('login:' . $c['ip'] . ':' . $id, 8, 900);
    if (strpos($id, '@') !== false) {
        $u = row('SELECT * FROM users WHERE email = ?', [$id]);
    } else {
        $u = row('SELECT * FROM users WHERE phone_norm = ?', [norm_phone($id)]);
    }
    $ok = verify_pw($pwd, $u['pass_hash'] ?? null);
    if ($u === null || !$ok) {
        throw new HttpError(401, 'Неверный email/телефон или пароль');
    }
    if ($u['status'] !== 'active') {
        throw new HttpError(403, 'Аккаунт заблокирован. Обратитесь в администрацию.');
    }
    q('UPDATE users SET last_login = ? WHERE id = ?', [now(), $u['id']]);
    $u['last_login'] = now();
    create_session((int) $u['id']);
    json_out(200, ['user' => public_user($u)]);
});

route('POST', '/auth/logout', null, function () {
    $t = session_token();
    if ($t !== null) {
        q('DELETE FROM sessions WHERE token_hash = ?', [sha($t)]);
    }
    put_cookie('', time() - 3600);
    json_out(200, ['ok' => true]);
});

route('POST', '/auth/password', 'user', function ($c) {
    $u = $c['user'];
    $b = $c['body'];
    limit('pwd:' . $u['id'], 10, 3600);
    $current = is_string($b['current'] ?? null) ? $b['current'] : '';
    if (!verify_pw($current, $u['pass_hash'])) {
        throw new HttpError(400, 'Текущий пароль указан неверно', 'current');
    }
    $next = check_password($b['next'] ?? null);
    q('UPDATE users SET pass_hash = ? WHERE id = ?', [hash_pw($next), $u['id']]);
    q('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?', [$u['id'], sha((string) session_token())]);
    json_out(200, ['ok' => true]);
});

/* ============ ПУБЛИЧНЫЕ ДАННЫЕ И ФОРМЫ ============ */

route('GET', '/reviews', null, function () {
    json_out(200, ['reviews' => rows(
        "SELECT id, name, rating, text, created_at FROM reviews
         WHERE status = 'approved' ORDER BY created_at DESC LIMIT 30"
    )]);
});

route('POST', '/reviews', 'user', function ($c) {
    $u = $c['user'];
    $b = $c['body'];
    limit('rev:' . $u['id'], 5, 3600);
    $name = vopt($b['name'] ?? null, 100, 'Имя', 'name');
    if ($name === '') {
        $name = $u['name'];
    }
    $rating = filter_var($b['rating'] ?? null, FILTER_VALIDATE_INT);
    if ($rating === false || $rating < 1 || $rating > 5) {
        throw bad('Оценка от 1 до 5', 'rating');
    }
    $text = vstr($b['text'] ?? null, 10, 2000, 'Отзыв', 'text');
    $status = ROLE_RANK[$u['role']] >= ROLE_RANK['moderator'] ? 'approved' : 'pending';
    q('INSERT INTO reviews (user_id, name, rating, text, status, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        [$u['id'], $name, $rating, $text, $status, now()]);
    json_out(201, ['id' => last_id(), 'status' => $status]);
});

route('POST', '/appointments', null, function ($c) {
    $b = $c['body'];
    limit('appt:' . $c['ip'], 10, 3600);
    $name = vstr($b['name'] ?? null, 2, 100, 'Имя', 'name');
    $ph = vphone($b['phone'] ?? null);
    $mail = vemail($b['email'] ?? null, false);
    $specialist = vstr($b['specialist'] ?? null, 2, 60, 'Специалист', 'specialist');
    $date = vopt($b['date'] ?? null, 10, 'Дата', 'date');
    if ($date !== '') {
        $d = DateTime::createFromFormat('!Y-m-d', $date);
        if ($d === false || $d->format('Y-m-d') !== $date) {
            throw bad('Некорректная дата', 'date');
        }
        if ($date < date('Y-m-d', time() - 86400)) {
            throw bad('Дата не может быть в прошлом', 'date');
        }
    }
    q("INSERT INTO appointments (user_id, name, phone, email, specialist, date, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'new', ?)",
        [$c['user']['id'] ?? null, $name, $ph['raw'], $mail, $specialist, $date === '' ? null : $date, now()]);
    json_out(201, ['id' => last_id()]);
});

route('POST', '/resumes', null, function ($c) {
    $b = $c['body'];
    limit('resume:' . $c['ip'], 5, 3600);
    $fio = vstr($b['fio'] ?? null, 3, 100, 'ФИО', 'fio');
    $ph = vphone($b['phone'] ?? null);
    $mail = vemail($b['email'] ?? null);
    $position = vstr($b['position'] ?? null, 2, 80, 'Должность', 'position');
    $experience = vopt($b['experience'] ?? null, 3000, 'Опыт работы', 'experience');
    q("INSERT INTO resumes (user_id, fio, phone, email, position, experience, status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'new', ?)",
        [$c['user']['id'] ?? null, $fio, $ph['raw'], $mail, $position, $experience, now()]);
    json_out(201, ['id' => last_id()]);
});

/* ============ ЛИЧНЫЙ КАБИНЕТ ============ */

route('GET', '/me/overview', 'user', function ($c) {
    $id = $c['user']['id'];
    json_out(200, [
        'appointments' => rows('SELECT id, specialist, date, status, created_at FROM appointments WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', [$id]),
        'reviews' => rows('SELECT id, rating, text, status, created_at FROM reviews WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', [$id]),
    ]);
});

route('POST', '/appointments/:id/cancel', 'user', function ($c) {
    $id = to_id($c['params']['id']);
    $a = row('SELECT * FROM appointments WHERE id = ? AND user_id = ?', [$id, $c['user']['id']]);
    if ($a === null) {
        throw new HttpError(404, 'Запись не найдена');
    }
    if (!in_array($a['status'], ['new', 'confirmed'], true)) {
        throw bad('Эту запись уже нельзя отменить');
    }
    q("UPDATE appointments SET status = 'cancelled' WHERE id = ?", [$id]);
    json_out(200, ['ok' => true]);
});

/* ============ ПЕРСОНАЛ (модератор и выше) ============ */

route('GET', '/admin/stats', 'moderator', function ($c) {
    $stats = [
        'appointments' => (int) val('SELECT COUNT(*) FROM appointments'),
        'newAppointments' => (int) val("SELECT COUNT(*) FROM appointments WHERE status = 'new'"),
        'reviews' => (int) val('SELECT COUNT(*) FROM reviews'),
        'pendingReviews' => (int) val("SELECT COUNT(*) FROM reviews WHERE status = 'pending'"),
    ];
    if ($c['user']['role'] === 'admin') {
        $stats['users'] = (int) val('SELECT COUNT(*) FROM users');
        $stats['resumes'] = (int) val('SELECT COUNT(*) FROM resumes');
        $stats['newResumes'] = (int) val("SELECT COUNT(*) FROM resumes WHERE status = 'new'");
    }
    json_out(200, ['stats' => $stats]);
});

route('GET', '/admin/appointments', 'moderator', function () {
    json_out(200, ['items' => rows(
        "SELECT * FROM appointments ORDER BY
         CASE status WHEN 'new' THEN 0 WHEN 'confirmed' THEN 1 ELSE 2 END, created_at DESC LIMIT 300"
    )]);
});

route('PATCH', '/admin/appointments/:id', 'moderator', function ($c) {
    $id = to_id($c['params']['id']);
    $status = one_of($c['body']['status'] ?? null, ['new', 'confirmed', 'done', 'cancelled'], 'Статус');
    if (q('UPDATE appointments SET status = ? WHERE id = ?', [$status, $id])->rowCount() === 0) {
        throw new HttpError(404, 'Запись не найдена');
    }
    audit($c['user'], 'appointment.status', "запись #{$id} → {$status}");
    json_out(200, ['ok' => true]);
});

route('GET', '/admin/reviews', 'moderator', function () {
    json_out(200, ['items' => rows(
        "SELECT * FROM reviews ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, created_at DESC LIMIT 300"
    )]);
});

route('PATCH', '/admin/reviews/:id', 'moderator', function ($c) {
    $id = to_id($c['params']['id']);
    $status = one_of($c['body']['status'] ?? null, ['pending', 'approved', 'rejected'], 'Статус');
    if (q('UPDATE reviews SET status = ? WHERE id = ?', [$status, $id])->rowCount() === 0) {
        throw new HttpError(404, 'Отзыв не найден');
    }
    audit($c['user'], 'review.status', "отзыв #{$id} → {$status}");
    json_out(200, ['ok' => true]);
});

route('DELETE', '/admin/reviews/:id', 'moderator', function ($c) {
    $id = to_id($c['params']['id']);
    if (q('DELETE FROM reviews WHERE id = ?', [$id])->rowCount() === 0) {
        throw new HttpError(404, 'Отзыв не найден');
    }
    audit($c['user'], 'review.delete', "отзыв #{$id}");
    json_out(200, ['ok' => true]);
});

/* ============ АДМИНИСТРАТОР ============ */

route('GET', '/admin/resumes', 'admin', function () {
    json_out(200, ['items' => rows('SELECT * FROM resumes ORDER BY created_at DESC LIMIT 300')]);
});

route('PATCH', '/admin/resumes/:id', 'admin', function ($c) {
    $id = to_id($c['params']['id']);
    $status = one_of($c['body']['status'] ?? null, ['new', 'viewed'], 'Статус');
    if (q('UPDATE resumes SET status = ? WHERE id = ?', [$status, $id])->rowCount() === 0) {
        throw new HttpError(404, 'Резюме не найдено');
    }
    json_out(200, ['ok' => true]);
});

route('DELETE', '/admin/resumes/:id', 'admin', function ($c) {
    $id = to_id($c['params']['id']);
    if (q('DELETE FROM resumes WHERE id = ?', [$id])->rowCount() === 0) {
        throw new HttpError(404, 'Резюме не найдено');
    }
    audit($c['user'], 'resume.delete', "резюме #{$id}");
    json_out(200, ['ok' => true]);
});

route('GET', '/admin/users', 'admin', function () {
    json_out(200, ['items' => rows(
        "SELECT id, name, email, phone, role, status, created_at, last_login FROM users
         ORDER BY CASE role WHEN 'admin' THEN 0 WHEN 'moderator' THEN 1 ELSE 2 END, created_at DESC"
    )]);
});

function other_active_admins(int $exceptId): int
{
    return (int) val("SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active' AND id != ?", [$exceptId]);
}

route('PATCH', '/admin/users/:id', 'admin', function ($c) {
    $me = $c['user'];
    $b = $c['body'];
    $id = to_id($c['params']['id']);
    $target = row('SELECT * FROM users WHERE id = ?', [$id]);
    if ($target === null) {
        throw new HttpError(404, 'Пользователь не найден');
    }
    $changes = [];
    if (isset($b['role'])) {
        $role = one_of($b['role'], ROLES, 'Роль');
        if ($id === (int) $me['id'] && $role !== 'admin') {
            throw bad('Нельзя снять роль администратора с самого себя');
        }
        if ($target['role'] === 'admin' && $role !== 'admin' && other_active_admins($id) < 1) {
            throw bad('Нельзя убрать последнего администратора');
        }
        if ($role !== $target['role']) {
            q('UPDATE users SET role = ? WHERE id = ?', [$role, $id]);
            $changes[] = "роль {$target['role']} → {$role}";
        }
    }
    if (isset($b['status'])) {
        $status = one_of($b['status'], ['active', 'blocked'], 'Статус');
        if ($id === (int) $me['id'] && $status !== 'active') {
            throw bad('Нельзя заблокировать самого себя');
        }
        if ($target['role'] === 'admin' && $status === 'blocked' && other_active_admins($id) < 1) {
            throw bad('Нельзя заблокировать последнего администратора');
        }
        if ($status !== $target['status']) {
            q('UPDATE users SET status = ? WHERE id = ?', [$status, $id]);
            if ($status === 'blocked') {
                q('DELETE FROM sessions WHERE user_id = ?', [$id]);
            }
            $changes[] = "статус {$target['status']} → {$status}";
        }
    }
    if ($changes) {
        audit($me, 'user.update', $target['email'] . ': ' . implode(', ', $changes));
    }
    json_out(200, ['ok' => true]);
});

route('POST', '/admin/users/:id/reset-password', 'admin', function ($c) {
    $id = to_id($c['params']['id']);
    $target = row('SELECT * FROM users WHERE id = ?', [$id]);
    if ($target === null) {
        throw new HttpError(404, 'Пользователь не найден');
    }
    $temp = random_password(12);
    q('UPDATE users SET pass_hash = ? WHERE id = ?', [hash_pw($temp), $id]);
    q('DELETE FROM sessions WHERE user_id = ?', [$id]);
    audit($c['user'], 'user.reset_password', $target['email']);
    json_out(200, ['password' => $temp]);
});

route('DELETE', '/admin/users/:id', 'admin', function ($c) {
    $id = to_id($c['params']['id']);
    $target = row('SELECT * FROM users WHERE id = ?', [$id]);
    if ($target === null) {
        throw new HttpError(404, 'Пользователь не найден');
    }
    if ($id === (int) $c['user']['id']) {
        throw bad('Нельзя удалить самого себя');
    }
    if ($target['role'] === 'admin' && other_active_admins($id) < 1) {
        throw bad('Нельзя удалить последнего администратора');
    }
    q('DELETE FROM users WHERE id = ?', [$id]);
    audit($c['user'], 'user.delete', $target['email']);
    json_out(200, ['ok' => true]);
});

route('GET', '/admin/audit', 'admin', function () {
    json_out(200, ['items' => rows('SELECT * FROM audit_log ORDER BY id DESC LIMIT 100')]);
});

/* ============ РЕКЛАМА ============ */

const AD_FIELDS = [
    'provider' => null,
    'adsense_client' => '/^ca-pub-\d{10,20}$/',
    'adsense_slot1' => '/^\d{6,15}$/',
    'adsense_slot2' => '/^\d{6,15}$/',
    'yandex_block1' => '/^R-A-\d+-\d+$/',
    'yandex_block2' => '/^R-A-\d+-\d+$/',
];

function ad_settings(): array
{
    $out = [];
    foreach (AD_FIELDS as $k => $_) {
        $out[$k] = '';
    }
    $out['provider'] = 'house';
    foreach (rows('SELECT key, value FROM settings') as $r) {
        if (array_key_exists($r['key'], AD_FIELDS)) {
            $out[$r['key']] = $r['value'];
        }
    }
    return $out;
}

function ad_field(string $key, $v): string
{
    if ($key === 'provider') {
        return (string) one_of($v, ['off', 'house', 'adsense', 'yandex'], 'Источник рекламы');
    }
    $s = trim((string) ($v ?? ''));
    if ($s === '') {
        return '';
    }
    if (!preg_match(AD_FIELDS[$key], $s)) {
        throw bad("Неверный формат поля «{$key}»");
    }
    return $s;
}

function safe_url($v): string
{
    $s = vstr($v, 2, 500, 'Ссылка', 'url');
    if (preg_match('/^#[a-z]{3,20}$/', $s)) {
        return $s; // переход к разделу сайта, например #appointment
    }
    $scheme = strtolower((string) parse_url($s, PHP_URL_SCHEME));
    $host = (string) parse_url($s, PHP_URL_HOST);
    if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
        throw bad('Ссылка должна начинаться с http:// или https://', 'url');
    }
    return $s;
}

route('GET', '/ads', null, function () {
    json_out(200, [
        'ads' => ad_settings(),
        'house' => rows('SELECT id, title, text, url, slot FROM house_ads WHERE active = 1 ORDER BY id DESC LIMIT 20'),
    ]);
});

route('GET', '/admin/ads', 'admin', function () {
    json_out(200, ['settings' => ad_settings(), 'house' => rows('SELECT * FROM house_ads ORDER BY id DESC')]);
});

route('PUT', '/admin/ads', 'admin', function ($c) {
    $b = $c['body'];
    $clean = [];
    foreach (array_keys(AD_FIELDS) as $k) {
        if (array_key_exists($k, $b)) {
            $clean[$k] = ad_field($k, $b[$k]);
        }
    }
    $eff = array_merge(ad_settings(), $clean);
    if ($eff['provider'] === 'adsense' && !($eff['adsense_client'] !== '' && ($eff['adsense_slot1'] !== '' || $eff['adsense_slot2'] !== ''))) {
        throw bad('Для AdSense укажите client ID и хотя бы один slot');
    }
    if ($eff['provider'] === 'yandex' && $eff['yandex_block1'] === '' && $eff['yandex_block2'] === '') {
        throw bad('Для Яндекса укажите хотя бы один blockId');
    }
    foreach ($clean as $k => $v) {
        q('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', [$k, $v]);
    }
    audit($c['user'], 'ads.settings', 'источник: ' . $eff['provider']);
    json_out(200, ['ok' => true]);
});

route('POST', '/admin/ads/house', 'admin', function ($c) {
    $b = $c['body'];
    $title = vstr($b['title'] ?? null, 3, 80, 'Заголовок', 'title');
    $text = vstr($b['text'] ?? null, 3, 200, 'Текст', 'text');
    $url = safe_url($b['url'] ?? null);
    $slot = (int) ($b['slot'] ?? 0);
    if (!in_array($slot, [0, 1, 2], true)) {
        $slot = 0;
    }
    q('INSERT INTO house_ads (title, text, url, slot, active, created_at) VALUES (?, ?, ?, ?, 1, ?)', [$title, $text, $url, $slot, now()]);
    audit($c['user'], 'ads.house.create', $title);
    json_out(201, ['id' => last_id()]);
});

route('PATCH', '/admin/ads/house/:id', 'admin', function ($c) {
    $id = to_id($c['params']['id']);
    $active = filter_var($c['body']['active'] ?? false, FILTER_VALIDATE_BOOLEAN) ? 1 : 0;
    if (q('UPDATE house_ads SET active = ? WHERE id = ?', [$active, $id])->rowCount() === 0) {
        throw new HttpError(404, 'Баннер не найден');
    }
    audit($c['user'], 'ads.house.toggle', "#{$id} → " . ($active ? 'вкл' : 'выкл'));
    json_out(200, ['ok' => true]);
});

route('DELETE', '/admin/ads/house/:id', 'admin', function ($c) {
    $id = to_id($c['params']['id']);
    if (q('DELETE FROM house_ads WHERE id = ?', [$id])->rowCount() === 0) {
        throw new HttpError(404, 'Баннер не найден');
    }
    audit($c['user'], 'ads.house.delete', "#{$id}");
    json_out(200, ['ok' => true]);
});


/* ============ ПОДДЕРЖКА ============ */
route('POST', '/support/tickets', null, function ($c) {
    $b = $c['body'];
    limit('support:' . $c['ip'], 12, 3600);
    $message = vstr($b['message'] ?? null, 2, 3000, 'Сообщение', 'message');
    $u = $c['user'];
    $guestToken = '';
    $guestName = '';
    $guestEmail = '';
    if (!$u) {
        $guestToken = vstr($b['guest_token'] ?? null, 24, 100, 'Токен обращения');
        $guestName = vopt($b['name'] ?? null, 100, 'Имя');
        $guestEmail = vemail($b['email'] ?? null, false);
    }
    $subject = vopt($b['subject'] ?? null, 120, 'Тема');
    if ($subject === '') $subject = 'Обращение в поддержку';
    q("INSERT INTO support_tickets (user_id,guest_token,guest_name,guest_email,subject,status,created_at,updated_at)
       VALUES (?,?,?,?,?,'open',?,?)", [$u['id'] ?? null, $u ? null : $guestToken, $guestName, $guestEmail, $subject, now(), now()]);
    $id = last_id();
    q("INSERT INTO support_messages (ticket_id,sender_id,sender_role,message,created_at) VALUES (?,?,? ,?,?)",
      [$id, $u['id'] ?? null, $u['role'] ?? 'guest', $message, now()]);
    json_out(201, ['ticket_id' => $id]);
});

route('GET', '/support/tickets/:id', null, function ($c) {
    $id = to_id($c['params']['id']);
    $ticket = row('SELECT * FROM support_tickets WHERE id = ?', [$id]);
    if (!$ticket) throw new HttpError(404, 'Обращение не найдено');
    $u = $c['user'];
    if ($u && ROLE_RANK[$u['role']] >= ROLE_RANK['operator']) {
        // Оператор может читать все обращения.
    } elseif ($ticket['user_id'] !== null) {
        if (!$u || (int)$ticket['user_id'] !== (int)$u['id']) throw new HttpError(403, 'Нет доступа к обращению');
    } else {
        $token = (string)($_GET['token'] ?? '');
        if ($token === '' || !hash_equals((string)$ticket['guest_token'], $token)) throw new HttpError(403, 'Нет доступа к обращению');
    }
    json_out(200, ['ticket' => [
      'id'=>(int)$ticket['id'],'subject'=>$ticket['subject'],'status'=>$ticket['status'],
      'created_at'=>$ticket['created_at'],'updated_at'=>$ticket['updated_at'],
      'messages'=>rows('SELECT id,sender_role,message,created_at FROM support_messages WHERE ticket_id=? ORDER BY id ASC',[$id])
    ]]);
});

route('POST', '/support/tickets/:id/messages', null, function ($c) {
    $id = to_id($c['params']['id']);
    $ticket = row('SELECT * FROM support_tickets WHERE id=?',[$id]);
    if (!$ticket) throw new HttpError(404,'Обращение не найдено');
    if ($ticket['status'] === 'closed') throw bad('Обращение закрыто');
    $u = $c['user']; $b = $c['body'];
    $staff = $u && ROLE_RANK[$u['role']] >= ROLE_RANK['operator'];
    if (!$staff) {
        if ($ticket['user_id'] !== null) {
            if (!$u || (int)$ticket['user_id'] !== (int)$u['id']) throw new HttpError(403,'Нет доступа к обращению');
        } else {
            $token = (string)($b['guest_token'] ?? '');
            if ($token === '' || !hash_equals((string)$ticket['guest_token'],$token)) throw new HttpError(403,'Нет доступа к обращению');
        }
    }
    $message = vstr($b['message'] ?? null, 1, 3000, 'Сообщение');
    q('INSERT INTO support_messages (ticket_id,sender_id,sender_role,message,created_at) VALUES (?,?,?,?,?)',
      [$id,$u['id'] ?? null,$u['role'] ?? 'guest',$message,now()]);
    q('UPDATE support_tickets SET updated_at=? WHERE id=?',[now(),$id]);
    json_out(201,['ok'=>true]);
});

route('GET', '/operator/tickets', 'operator', function () {
    json_out(200,['items'=>rows("SELECT t.*, u.name AS user_name, u.email AS user_email,
      (SELECT message FROM support_messages m WHERE m.ticket_id=t.id ORDER BY m.id DESC LIMIT 1) AS last_message,
      (SELECT COUNT(*) FROM support_messages m WHERE m.ticket_id=t.id) AS message_count
      FROM support_tickets t LEFT JOIN users u ON u.id=t.user_id
      ORDER BY CASE t.status WHEN 'open' THEN 0 ELSE 1 END,t.updated_at DESC LIMIT 300")]);
});

route('GET', '/operator/tickets/:id', 'operator', function ($c) {
    $id=to_id($c['params']['id']);
    $ticket=row("SELECT t.*,u.name AS user_name,u.email AS user_email FROM support_tickets t LEFT JOIN users u ON u.id=t.user_id WHERE t.id=?",[$id]);
    if(!$ticket) throw new HttpError(404,'Обращение не найдено');
    json_out(200,['ticket'=>$ticket,'messages'=>rows('SELECT id,sender_role,message,created_at FROM support_messages WHERE ticket_id=? ORDER BY id ASC',[$id])]);
});

route('POST', '/operator/tickets/:id/messages', 'operator', function ($c) {
    $id=to_id($c['params']['id']); $b=$c['body'];
    $ticket=row('SELECT id,status FROM support_tickets WHERE id=?',[$id]);
    if(!$ticket) throw new HttpError(404,'Обращение не найдено');
    if($ticket['status']==='closed') throw bad('Обращение закрыто');
    $message=vstr($b['message']??null,1,3000,'Сообщение');
    q('INSERT INTO support_messages (ticket_id,sender_id,sender_role,message,created_at) VALUES (?,?,?,?,?)',[$id,$c['user']['id'],'operator',$message,now()]);
    q('UPDATE support_tickets SET updated_at=?,assigned_to=? WHERE id=?',[now(),$c['user']['id'],$id]);
    json_out(201,['ok'=>true]);
});

route('PATCH', '/operator/tickets/:id', 'operator', function ($c) {
    $id=to_id($c['params']['id']);
    $status=one_of($c['body']['status']??null,['open','closed'],'Статус');
    if(q('UPDATE support_tickets SET status=?,updated_at=? WHERE id=?',[$status,now(),$id])->rowCount()===0) throw new HttpError(404,'Обращение не найдено');
    audit($c['user'],'support.ticket.status',"обращение #{$id} → {$status}");
    json_out(200,['ok'=>true]);
});


/* ============ ЗАПУСК ============ */

try {
    $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
    // Некоторые хостинги блокируют PUT/PATCH/DELETE — клиент шлёт POST с этим заголовком
    if ($method === 'POST' && !empty($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'])) {
        $override = strtoupper($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE']);
        if (in_array($override, ['PUT', 'PATCH', 'DELETE'], true)) {
            $method = $override;
        }
    }
    $path = '/' . trim((string) ($_GET['r'] ?? ''), '/');
    dispatch($method, $path);
} catch (HttpError $e) {
    json_out($e->status, ['error' => $e->getMessage(), 'field' => $e->field]);
} catch (Throwable $e) {
    error_log('[rbcemp] ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
    json_out(500, ['error' => 'Внутренняя ошибка сервера']);
}
