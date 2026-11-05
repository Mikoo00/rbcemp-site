<?php
/*
  Консольные команды (запускать из консоли Open Server, из папки сайта):
    php cli.php make-admin email@example.ru
    php cli.php set-password email@example.ru НовыйПароль123
*/
if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
require __DIR__ . '/app/bootstrap.php';

$cmd = $argv[1] ?? '';
$email = strtolower(trim($argv[2] ?? ''));
$pwd = $argv[3] ?? '';

try {
    $u = $email !== '' ? row('SELECT * FROM users WHERE email = ?', [$email]) : null;
    if ($cmd === 'make-admin') {
        if ($u === null) {
            fwrite(STDERR, "Пользователь не найден\n");
            exit(1);
        }
        q("UPDATE users SET role = 'admin', status = 'active' WHERE id = ?", [$u['id']]);
        echo "{$u['email']} теперь администратор\n";
    } elseif ($cmd === 'set-password') {
        if ($u === null) {
            fwrite(STDERR, "Пользователь не найден\n");
            exit(1);
        }
        check_password($pwd);
        q('UPDATE users SET pass_hash = ? WHERE id = ?', [hash_pw($pwd), $u['id']]);
        q('DELETE FROM sessions WHERE user_id = ?', [$u['id']]);
        echo "Пароль обновлён\n";
    } else {
        fwrite(STDERR, "Команды: make-admin <email> | set-password <email> <пароль>\n");
        exit(1);
    }
} catch (Throwable $e) {
    fwrite(STDERR, 'Ошибка: ' . $e->getMessage() . "\n");
    exit(1);
}
