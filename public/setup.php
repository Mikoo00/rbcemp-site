<?php
/*
  Первоначальная настройка: создание главного администратора.
  Доступна только пока нет ни одного администратора, и только:
   - с вашего компьютера (localhost), либо
   - по ключу: setup.php?key=... (ключ задаётся в config.php, параметр setup_key).
*/
require __DIR__ . '/../app/bootstrap.php';

header('Content-Type: text/html; charset=utf-8');
header('X-Frame-Options: DENY');
header('Cache-Control: no-store');

function h($s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}

function page(string $title, string $body): void
{
    echo '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<title>' . h($title) . '</title><style>'
        . 'body{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#eef6fb;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;color:#1e293b}'
        . '.card{background:#fff;border-radius:18px;padding:32px;max-width:440px;width:92%;box-shadow:0 10px 40px rgba(14,165,233,.15)}'
        . 'h1{font-size:1.3rem;margin:0 0 6px}p{color:#64748b;font-size:.9rem;line-height:1.5}'
        . 'label{display:block;font-size:.8rem;font-weight:600;margin:14px 0 4px}'
        . 'input{width:100%;box-sizing:border-box;padding:11px 12px;border:1.5px solid #cbd5e1;border-radius:10px;font-size:.95rem}'
        . 'button{margin-top:20px;width:100%;padding:12px;border:0;border-radius:10px;background:#0ea5e9;color:#fff;font-weight:700;font-size:1rem;cursor:pointer}'
        . '.err{background:#fee2e2;color:#b91c1c;padding:10px 12px;border-radius:10px;font-size:.88rem;margin-top:12px}'
        . '.ok{background:#dcfce7;color:#166534;padding:10px 12px;border-radius:10px;font-size:.88rem;margin-top:12px}'
        . 'a{color:#0284c7}</style></head><body><div class="card">' . $body . '</div></body></html>';
    exit;
}

try {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    $isLocal = in_array($ip, ['127.0.0.1', '::1'], true);
    $key = (string) cfg('setup_key', '');
    $givenKey = (string) ($_GET['key'] ?? $_POST['key'] ?? '');
    $keyOk = $key !== '' && hash_equals($key, $givenKey);

    if (!$isLocal && !$keyOk) {
        http_response_code(403);
        page('Доступ закрыт', '<h1>Доступ закрыт</h1><p>Настройка доступна только с компьютера, где запущен сайт, '
            . 'или по ключу. Задайте <code>setup_key</code> в файле <code>config.php</code> и откройте '
            . '<code>setup.php?key=ВАШ_КЛЮЧ</code>.</p>');
    }

    if ((int) val("SELECT COUNT(*) FROM users WHERE role = 'admin'") > 0) {
        page('Уже настроено', '<h1>Администратор уже создан</h1><p>Войдите на сайте под его логином. '
            . 'Если забыли пароль, выполните в консоли: <code>php cli.php set-password email новый_пароль</code>.</p>'
            . '<p><a href="index.html">Перейти на сайт</a></p>');
    }

    $error = '';
    $done = false;
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        if ($origin !== '' && strcasecmp((string) parse_url($origin, PHP_URL_HOST) . (parse_url($origin, PHP_URL_PORT) ? ':' . parse_url($origin, PHP_URL_PORT) : ''), $_SERVER['HTTP_HOST'] ?? '') !== 0) {
            throw new HttpError(403, 'Запрещённый источник запроса');
        }
        try {
            $name = vstr($_POST['name'] ?? null, 3, 100, 'ФИО');
            $email = vemail($_POST['email'] ?? null);
            $phone = trim((string) ($_POST['phone'] ?? ''));
            $pwd = check_password($_POST['password'] ?? null);
            if (($_POST['password2'] ?? '') !== $pwd) {
                throw bad('Пароли не совпадают');
            }
            create_admin($name, $email, $phone, $pwd);
            $done = true;
        } catch (HttpError $e) {
            $error = $e->getMessage();
        }
    }

    if ($done) {
        page('Готово', '<h1>Администратор создан</h1><div class="ok">Теперь войдите на сайте под этим email и паролем.</div>'
            . '<p>Сменить пароль можно в профиле. Файл <code>setup.php</code> теперь ничего не делает, но его можно удалить.</p>'
            . '<p><a href="index.html">Перейти на сайт</a></p>');
    }

    $keyField = $keyOk ? '<input type="hidden" name="key" value="' . h($givenKey) . '">' : '';
    page('Первоначальная настройка', '<h1>Создание администратора</h1><p>Это главный аккаунт сайта: он выдаёт роли другим пользователям.</p>'
        . ($error !== '' ? '<div class="err">' . h($error) . '</div>' : '')
        . '<form method="post">' . $keyField
        . '<label>ФИО</label><input name="name" required value="' . h($_POST['name'] ?? '') . '">'
        . '<label>Email (логин)</label><input name="email" type="email" required value="' . h($_POST['email'] ?? '') . '">'
        . '<label>Телефон (необязательно)</label><input name="phone" value="' . h($_POST['phone'] ?? '') . '">'
        . '<label>Пароль (минимум 8 символов)</label><input name="password" type="password" required minlength="8">'
        . '<label>Повторите пароль</label><input name="password2" type="password" required minlength="8">'
        . '<button type="submit">Создать администратора</button></form>');
} catch (HttpError $e) {
    http_response_code($e->status);
    page('Ошибка', '<h1>Ошибка</h1><div class="err">' . h($e->getMessage()) . '</div>');
} catch (Throwable $e) {
    error_log('[rbcemp setup] ' . $e->getMessage());
    http_response_code(500);
    page('Ошибка', '<h1>Ошибка</h1><div class="err">Внутренняя ошибка. Проверьте, что включено расширение pdo_sqlite и папка data/ доступна для записи.</div>');
}
