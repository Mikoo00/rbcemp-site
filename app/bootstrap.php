<?php
/*
  Ядро: настройки, база данных (SQLite через PDO), проверки данных, сессии.
  Требуется PHP 8.1 или новее (проверено на синтаксис PHP 8.5), расширение pdo_sqlite.
*/

if (version_compare(PHP_VERSION, '8.1.0', '<')) {
    http_response_code(500);
    exit('Нужен PHP 8.1 или новее');
}

$GLOBALS['CFG'] = require __DIR__ . '/../config.php';
date_default_timezone_set($GLOBALS['CFG']['timezone'] ?? 'UTC');
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

const ROLES = ['user', 'operator', 'moderator', 'admin'];
const ROLE_RANK = ['user' => 1, 'operator' => 2, 'moderator' => 3, 'admin' => 4];

function cfg(string $key, $default = null)
{
    return $GLOBALS['CFG'][$key] ?? $default;
}

class HttpError extends Exception
{
    public int $status;
    public ?string $field;

    public function __construct(int $status, string $message, ?string $field = null)
    {
        parent::__construct($message);
        $this->status = $status;
        $this->field = $field;
    }
}

function bad(string $message, ?string $field = null): HttpError
{
    return new HttpError(400, $message, $field);
}

/* ============ БАЗА ДАННЫХ ============ */

function db(): PDO
{
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }
    if (!extension_loaded('pdo_sqlite')) {
        throw new HttpError(500, 'В PHP не включено расширение pdo_sqlite. Включите его в настройках PHP в Open Server.');
    }
    $path = cfg('db_path');
    $dir = dirname($path);
    if (!is_dir($dir)) {
        @mkdir($dir, 0775, true);
    }
    $pdo = new PDO('sqlite:' . $path);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->exec('PRAGMA foreign_keys = ON');
    $pdo->exec('PRAGMA busy_timeout = 5000');
    migrate($pdo);
    return $pdo;
}

function migrate(PDO $pdo): void
{
    $version = (int) $pdo->query('PRAGMA user_version')->fetchColumn();
    if ($version >= 2) {
        return;
    }
    if ($version >= 1) {
        // Расширяем список ролей без потери существующих пользователей и связанных записей.
        $pdo->exec('PRAGMA foreign_keys = OFF');
        $pdo->exec("CREATE TABLE users_new (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE COLLATE NOCASE, phone TEXT NOT NULL,
          phone_norm TEXT NOT NULL, pass_hash TEXT NOT NULL,
          role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','operator','moderator','admin')),
          status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','blocked')),
          created_at TEXT NOT NULL, last_login TEXT
        )");
        $pdo->exec('INSERT INTO users_new SELECT id,name,email,phone,phone_norm,pass_hash,role,status,created_at,last_login FROM users');
        $pdo->exec('DROP TABLE users');
        $pdo->exec('ALTER TABLE users_new RENAME TO users');
        $pdo->exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users(phone_norm)');
        $pdo->exec('PRAGMA foreign_keys = ON');
        $pdo->exec("CREATE TABLE IF NOT EXISTS support_tickets (
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
          guest_token TEXT, guest_name TEXT, guest_email TEXT,
          subject TEXT NOT NULL DEFAULT 'Обращение в поддержку',
          status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed')),
          assigned_to INTEGER REFERENCES users(id) ON DELETE SET NULL,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        )");
        $pdo->exec("CREATE TABLE IF NOT EXISTS support_messages (
          id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
          sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL, sender_role TEXT NOT NULL,
          message TEXT NOT NULL, created_at TEXT NOT NULL
        )");
        $pdo->exec('CREATE INDEX IF NOT EXISTS idx_support_ticket_updated ON support_tickets(updated_at)');
        $pdo->exec('PRAGMA user_version = 2');
        return;
    }
    $pdo->exec("
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  phone TEXT NOT NULL,
  phone_norm TEXT NOT NULL,
  pass_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','operator','moderator','admin')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','blocked')),
  created_at TEXT NOT NULL,
  last_login TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_phone ON users(phone_norm);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS appointments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  name TEXT NOT NULL, phone TEXT NOT NULL, email TEXT,
  specialist TEXT NOT NULL, date TEXT,
  status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','confirmed','done','cancelled')),
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  name TEXT NOT NULL, rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
  text TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS resumes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  fio TEXT NOT NULL, phone TEXT NOT NULL, email TEXT NOT NULL,
  position TEXT NOT NULL, experience TEXT,
  status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','viewed')),
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_id INTEGER, actor_name TEXT,
  action TEXT NOT NULL, details TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS house_ads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL, text TEXT NOT NULL, url TEXT NOT NULL,
  slot INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rate_limits (
  k TEXT PRIMARY KEY,
  c INTEGER NOT NULL,
  reset_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS support_tickets (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  guest_token TEXT, guest_name TEXT, guest_email TEXT,
  subject TEXT NOT NULL DEFAULT 'Обращение в поддержку',
  status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','closed')),
  assigned_to INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS support_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER NOT NULL REFERENCES support_tickets(id) ON DELETE CASCADE,
  sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL, sender_role TEXT NOT NULL,
  message TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_support_ticket_updated ON support_tickets(updated_at);
");
    $pdo->exec('PRAGMA user_version = 2');
    seed_reviews($pdo);
    seed_house_ads($pdo);
}

function seed_house_ads(PDO $pdo): void
{
    $st = $pdo->prepare("INSERT OR IGNORE INTO meta (key, value) VALUES ('seed_house_ads', '1')");
    $st->execute();
    if ($st->rowCount() !== 1) {
        return;
    }
    $ins = $pdo->prepare('INSERT INTO house_ads (title, text, url, slot, active, created_at) VALUES (?, ?, ?, ?, 1, ?)');
    $ins->execute(['Диспансеризация для всей семьи', 'Профилактический осмотр поможет выявить заболевания на ранней стадии. Запишитесь онлайн.', '#appointment', 1, now()]);
    $ins->execute(['Круглосуточная экстренная помощь', 'Наши специалисты на связи 24/7. Контакты и адрес — в разделе «Контакты».', '#contacts', 2, now()]);
}

function seed_reviews(PDO $pdo): void
{
    $st = $pdo->prepare("INSERT OR IGNORE INTO meta (key, value) VALUES ('seed_reviews', '1')");
    $st->execute();
    if ($st->rowCount() !== 1) {
        return; // уже заполнено
    }
    $seed = [
        ['Анна Петрова', 5, 'Очень благодарна врачам за профессионализм и внимательное отношение. Получила качественную помощь в экстренной ситуации. Спасибо!', '2026-10-15T09:00:00.000Z'],
        ['Иван Сидоров', 5, 'Отличная больница! Современное оборудование, квалифицированные специалисты. Операцию провели на высшем уровне. Рекомендую!', '2026-10-10T09:00:00.000Z'],
        ['Мария Константинова', 4, 'Проходила диспансеризацию. Всё организовано чётко, врачи внимательные. Единственное — пришлось немного подождать, но в целом довольна.', '2026-10-05T09:00:00.000Z'],
    ];
    $ins = $pdo->prepare("INSERT INTO reviews (user_id, name, rating, text, status, created_at) VALUES (NULL, ?, ?, ?, 'approved', ?)");
    foreach ($seed as $s) {
        $ins->execute($s);
    }
}

function q(string $sql, array $params = []): PDOStatement
{
    $st = db()->prepare($sql);
    $i = 1;
    foreach ($params as $p) {
        if (is_int($p)) {
            $type = PDO::PARAM_INT;
        } elseif ($p === null) {
            $type = PDO::PARAM_NULL;
        } else {
            $type = PDO::PARAM_STR;
        }
        $st->bindValue($i++, $p, $type);
    }
    $st->execute();
    return $st;
}

function row(string $sql, array $params = []): ?array
{
    $r = q($sql, $params)->fetch();
    return $r === false ? null : $r;
}

function rows(string $sql, array $params = []): array
{
    return q($sql, $params)->fetchAll();
}

function val(string $sql, array $params = [])
{
    return q($sql, $params)->fetchColumn();
}

function last_id(): int
{
    return (int) db()->lastInsertId();
}

function now(): string
{
    return gmdate('Y-m-d\TH:i:s') . '.000Z';
}

/* ============ ПРОВЕРКА ДАННЫХ ============ */

function ulen(string $s): int
{
    if (function_exists('mb_strlen')) {
        return mb_strlen($s, 'UTF-8');
    }
    return (int) preg_match_all('/./us', $s);
}

function vstr($v, int $min, int $max, string $label, ?string $field = null): string
{
    if (!is_string($v)) {
        throw bad("Поле «{$label}» обязательно", $field);
    }
    $s = trim($v);
    $n = ulen($s);
    if ($n < $min) {
        throw bad("Поле «{$label}»: минимум {$min} симв.", $field);
    }
    if ($n > $max) {
        throw bad("Поле «{$label}»: максимум {$max} симв.", $field);
    }
    return $s;
}

function vopt($v, int $max, string $label, ?string $field = null): string
{
    if ($v === null || $v === '') {
        return '';
    }
    return vstr($v, 0, $max, $label, $field);
}

function vemail($v, bool $required = true): string
{
    if (!$required && ($v === null || (is_string($v) && trim($v) === ''))) {
        return '';
    }
    $s = strtolower(vstr($v, 5, 120, 'Email', 'email'));
    if (filter_var($s, FILTER_VALIDATE_EMAIL) === false) {
        throw bad('Некорректный email', 'email');
    }
    return $s;
}

function norm_phone($raw): string
{
    $d = preg_replace('/\D/', '', (string) $raw);
    if (strlen($d) === 11 && $d[0] === '8') {
        $d = '7' . substr($d, 1);
    }
    return $d;
}

function vphone($v): array
{
    $raw = vstr($v, 5, 30, 'Телефон', 'phone');
    $norm = norm_phone($raw);
    if (strlen($norm) < 10 || strlen($norm) > 15) {
        throw bad('Некорректный номер телефона', 'phone');
    }
    return ['raw' => $raw, 'norm' => $norm];
}

function to_id($v): int
{
    $n = filter_var($v, FILTER_VALIDATE_INT);
    if ($n === false || $n < 1) {
        throw bad('Некорректный идентификатор');
    }
    return $n;
}

function one_of($v, array $list, string $label)
{
    if (!in_array($v, $list, true)) {
        throw bad("Недопустимое значение поля «{$label}»");
    }
    return $v;
}

function check_password($p): string
{
    if (!is_string($p) || ulen($p) < 8) {
        throw bad('Пароль: минимум 8 символов', 'password');
    }
    if (strlen($p) > 72) {
        throw bad('Пароль слишком длинный (максимум 72 байта, около 36 русских букв)', 'password');
    }
    return $p;
}

function random_password(int $len = 12): string
{
    $alphabet = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    $max = strlen($alphabet) - 1;
    $out = '';
    for ($i = 0; $i < $len; $i++) {
        $out .= $alphabet[random_int(0, $max)];
    }
    return $out;
}

function hash_pw(string $pwd): string
{
    return password_hash($pwd, PASSWORD_DEFAULT);
}

function verify_pw(string $pwd, ?string $hash): bool
{
    static $dummy = null;
    if ($hash === null) {
        // Пользователь не найден: тратим то же время, чтобы нельзя было узнать, есть ли такой email
        if ($dummy === null) {
            $dummy = password_hash(bin2hex(random_bytes(8)), PASSWORD_DEFAULT);
        }
        password_verify($pwd, $dummy);
        return false;
    }
    return password_verify($pwd, $hash);
}

/* ============ ОГРАНИЧЕНИЕ ЧАСТОТЫ ЗАПРОСОВ ============ */

function limit(string $key, int $max, int $windowSec): void
{
    $t = time();
    q('DELETE FROM rate_limits WHERE reset_at < ?', [$t]);
    $r = row('SELECT c FROM rate_limits WHERE k = ?', [$key]);
    if ($r === null) {
        q('INSERT OR REPLACE INTO rate_limits (k, c, reset_at) VALUES (?, 1, ?)', [$key, $t + $windowSec]);
        return;
    }
    q('UPDATE rate_limits SET c = c + 1 WHERE k = ?', [$key]);
    if ($r['c'] + 1 > $max) {
        throw new HttpError(429, 'Слишком много попыток. Попробуйте позже.');
    }
}

/* ============ ЗАПРОС, ОТВЕТ, СЕССИИ ============ */

function client_ip(): string
{
    if (cfg('trust_proxy')) {
        $xff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
        if ($xff !== '') {
            return trim(explode(',', $xff)[0]);
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function is_https(): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off') {
        return true;
    }
    return cfg('trust_proxy') && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
}

function json_out(int $status, array $data): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}

function read_body(): array
{
    $len = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($len > 65536) {
        throw new HttpError(413, 'Слишком большой запрос');
    }
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') {
        return [];
    }
    if (strlen($raw) > 65536) {
        throw new HttpError(413, 'Слишком большой запрос');
    }
    $data = json_decode($raw, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw bad('Некорректный JSON');
    }
    return is_array($data) ? $data : [];
}

const SID_COOKIE = 'rbcemp_sid';

function put_cookie(string $value, int $expires): void
{
    setcookie(SID_COOKIE, $value, [
        'expires' => $expires,
        'path' => '/',
        'secure' => is_https(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
}

function sha(string $s): string
{
    return hash('sha256', $s);
}

function create_session(int $userId): void
{
    $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $days = (int) cfg('session_days', 7);
    $expires = time() + $days * 86400;
    q('DELETE FROM sessions WHERE expires_at < ?', [now()]);
    q('INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)', [
        sha($token), $userId, now(), gmdate('Y-m-d\TH:i:s', $expires) . '.000Z',
    ]);
    put_cookie($token, $expires);
}

function session_token(): ?string
{
    $t = $_COOKIE[SID_COOKIE] ?? null;
    return (is_string($t) && $t !== '') ? $t : null;
}

function current_user(): ?array
{
    static $loaded = false;
    static $user = null;
    if ($loaded) {
        return $user;
    }
    $loaded = true;
    $token = session_token();
    if ($token === null) {
        return null;
    }
    $user = row(
        "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ? AND s.expires_at > ? AND u.status = 'active'",
        [sha($token), now()]
    );
    return $user;
}

function public_user(?array $u): ?array
{
    if ($u === null) {
        return null;
    }
    return [
        'id' => (int) $u['id'], 'name' => $u['name'], 'email' => $u['email'], 'phone' => $u['phone'],
        'role' => $u['role'], 'status' => $u['status'],
        'created_at' => $u['created_at'], 'last_login' => $u['last_login'],
    ];
}

function audit(?array $actor, string $action, string $details = ''): void
{
    q('INSERT INTO audit_log (actor_id, actor_name, action, details, created_at) VALUES (?, ?, ?, ?, ?)', [
        $actor['id'] ?? null, $actor['name'] ?? 'система', $action, $details, now(),
    ]);
}

function create_admin(string $name, string $email, string $phone, string $password): void
{
    $existing = row('SELECT id FROM users WHERE email = ?', [$email]);
    if ($existing !== null) {
        q("UPDATE users SET role = 'admin', status = 'active', pass_hash = ? WHERE id = ?", [hash_pw($password), $existing['id']]);
        return;
    }
    $norm = norm_phone($phone);
    if ($norm === '' || row('SELECT 1 FROM users WHERE phone_norm = ?', [$norm]) !== null) {
        $phone = '+7 (000) 000-00-00';
        $norm = '0000000000' . random_int(1000, 9999);
    }
    q("INSERT INTO users (name, email, phone, phone_norm, pass_hash, role, status, created_at)
       VALUES (?, ?, ?, ?, ?, 'admin', 'active', ?)", [$name, $email, $phone, $norm, hash_pw($password), now()]);
}
