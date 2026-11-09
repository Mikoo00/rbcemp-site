# РБ №2-ЦЭМП — сайт больницы (Vercel + Supabase)

Статический сайт: `index.html`, `admin.html`, `supabase-api.js`, `img/`.
Серверной части в репозитории нет — данные и вход обслуживает Supabase
(таблицы с RLS + Edge Functions `admin-actions` и `guest-support`).

## Деплой
1. Удалите из репозитория старые файлы PHP-версии: `api.php`, `setup.php`, `cli.php`,
   `config.php`, `.htaccess`, папки `app/`, `data/`, `.osp/`.
   Особенно важно убрать `data/*.sqlite` и `config.php` — там были данные пользователей и ключи.
2. Загрузите файлы из этого архива в корень репозитория, сделайте commit и push в `main`.
   Vercel задеплоит сайт автоматически.

## Настройка Supabase
- Authentication → Providers → Email → отключите «Confirm email» (иначе новые пользователи
  не смогут войти до подтверждения почты).
- Authentication → URL Configuration → Site URL: `https://rbcemp-site.vercel.app`.

## Первый администратор
1. Зарегистрируйтесь на сайте обычным способом.
2. В Supabase → SQL Editor выполните (подставьте свою почту):
   `update public.profiles set role = 'admin' where email = 'ваша_почта@example.com';`
3. Откройте `/admin.html` и войдите.

## Важно
- В браузерный код попадает только publishable-ключ (`sb_publishable_...`).
  Secret-ключ (`sb_secret_...`) никогда не добавляйте в файлы сайта и репозиторий.
- Вход выполняется по email (вход по телефону из PHP-версии отключён,
  чтобы по номеру нельзя было узнать чужую почту).
