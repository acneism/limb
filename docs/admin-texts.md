# Texts of the administration

`limb.WithAdminTexts` replaces these texts and gives the administration languages of its own. A text that has `%s` or `%d` in it takes an argument, which the page fills in, and a replacement must use the same arguments, in any order, with `%[1]s` for the first one and so on. A text that takes none must not have a percent sign in it. A language that lacks a text shows the English one.

This file is made from the texts of the library by a test. After a text changes, make it again with `LIMB_UPDATE_DOCS=1 go test ./internal/adminui -run TestTheTableOfTheTextsIsUpToDate`.

| Key | English | Русский |
| --- | --- | --- |
| `back.to.login` | Back to the sign-in | Назад ко входу |
| `brand` | %s administration | Администрирование: %s |
| `code.failed` | The code is wrong, or it was used already. Wait for the next one and try again. | Код неверный или уже использован. Дождитесь следующего и попробуйте ещё раз. |
| `code.hint` | Enter the code of six digits that your authenticator app shows, or one of your recovery codes. | Введите шестизначный код из приложения-аутентификатора или один из резервных кодов. |
| `code.label` | Code | Код |
| `code.login` | Signing in as %s | Вход как %s |
| `code.restart` | Start again with the password | Начать заново с пароля |
| `code.submit` | Sign in | Войти |
| `code.title` | Confirm it is you | Подтвердите вход |
| `enroll.failed` | The code is wrong. Wait for the next one and try again. | Код неверный. Дождитесь следующего и попробуйте ещё раз. |
| `enroll.intro` | To sign in to the administration you need an authenticator app, for example one that your phone has or a password manager. Bind it now. | Чтобы входить в администрирование, нужно приложение-аутентификатор: например, встроенное в телефон или менеджер паролей. Привяжите его сейчас. |
| `enroll.label` | Code | Код |
| `enroll.manual` | Or type the key into the app by hand: | Или введите ключ в приложении вручную: |
| `enroll.open` | Open it in the authenticator app on this device | Открыть в приложении-аутентификаторе на этом устройстве |
| `enroll.qr` | QR code of the key of the authenticator | QR-код ключа аутентификатора |
| `enroll.secret` | Key | Ключ |
| `enroll.step1` | Scan this QR code with the app. | Отсканируйте этот QR-код в приложении. |
| `enroll.step2` | Enter the code of six digits that the app shows now. | Введите шестизначный код, который сейчас показывает приложение. |
| `enroll.submit` | Confirm and sign in | Подтвердить и войти |
| `enroll.title` | Bind an authenticator | Привязка аутентификатора |
| `error.400` | The request is not valid | Некорректный запрос |
| `error.400.text` | Go back and try again. | Вернитесь назад и попробуйте ещё раз. |
| `error.403` | The request was refused | Запрос отклонён |
| `error.403.text` | It did not come from a page of this site. Reload the page and try again. | Он пришёл не со страницы этого сайта. Обновите страницу и попробуйте ещё раз. |
| `error.404` | Page not found | Страница не найдена |
| `error.404.text` | There is nothing at this address. | По этому адресу ничего нет. |
| `error.405` | This method is not allowed | Метод не разрешён |
| `error.405.text` | The page cannot be used this way. | Страницей нельзя пользоваться так. |
| `error.413` | The request is too large | Запрос слишком большой |
| `error.413.text` | Send less. | Отправьте меньше. |
| `error.415` | The form is not in the expected format | Форма в неожиданном формате |
| `error.415.text` | Reload the page and try again. | Обновите страницу и попробуйте ещё раз. |
| `error.429` | Too many attempts | Слишком много попыток |
| `error.429.text` | Try again in %s. | Повторите через %s. |
| `error.500` | Something went wrong | Что-то пошло не так |
| `error.500.text` | Try again later. The administrator of the service can find the reason in the log. | Повторите позже. Причину найдёт в журнале администратор сервиса. |
| `error.csrf.expired` | The page has expired. Reload it and try again. | Страница устарела. Обновите её и попробуйте ещё раз. |
| `error.hours` | %d h | %d ч |
| `error.minutes` | %d min | %d мин |
| `error.seconds` | %d s | %d с |
| `home.account` | Your account | Ваша учётная запись |
| `home.account.text` | Change your password, bind another authenticator, make new recovery codes and see where you are signed in. | Смените пароль, привяжите другой аутентификатор, создайте новые резервные коды и посмотрите, где вы вошли. |
| `home.recovery` | You have %d recovery codes left. Make new ones on the page of your account. | Резервных кодов осталось: %d. Создайте новые на странице учётной записи. |
| `home.recovery.0` | You have no recovery codes left. Make new ones on the page of your account. | Резервных кодов не осталось. Создайте новые на странице учётной записи. |
| `home.signed.in` | You signed in at %s. | Вы вошли: %s. |
| `home.title` | Administration | Администрирование |
| `home.welcome` | Welcome, %s. | Добро пожаловать, %s. |
| `lang.label` | Language | Язык |
| `login.already` | You are signed in already. | Вы уже вошли. |
| `login.expired` | The sign-in has expired. Start again. | Вход устарел. Начните заново. |
| `login.failed` | The login or the password is wrong. | Неверный логин или пароль. |
| `login.limited` | Too many attempts. Try again in %s. | Слишком много попыток. Повторите через %s. |
| `login.login` | Login | Логин |
| `login.password` | Password | Пароль |
| `login.submit` | Continue | Продолжить |
| `login.title` | Sign in | Вход |
| `nav.account` | My account | Моя учётная запись |
| `nav.home` | Home | Главная |
| `nav.label` | Main menu | Главное меню |
| `nav.logout` | Sign out | Выйти |
| `recovery.done` | I have saved them, continue | Я сохранил(а) их, продолжить |
| `recovery.intro` | Keep these codes in a safe place, apart from your phone. If you lose the authenticator, each of them lets you sign in once. They are shown only now. | Сохраните эти коды в надёжном месте, отдельно от телефона. Если вы потеряете аутентификатор, каждый из них позволит войти один раз. Они показываются только сейчас. |
| `recovery.list` | Recovery codes | Резервные коды |
| `recovery.title` | Your recovery codes | Ваши резервные коды |
| `signed.in.as` | Signed in as %s | Вы вошли как %s |
| `skip` | Skip to the content | Перейти к содержимому |
| `time.utc` | %s UTC | %s UTC |
