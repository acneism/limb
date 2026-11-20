# Texts of the administration

`limb.WithAdminTexts` replaces these texts and gives the administration languages of its own. A text that has `%s` or `%d` in it takes an argument, which the page fills in, and a replacement must use the same arguments, in any order, with `%[1]s` for the first one and so on. A text that takes none must not have a percent sign in it. A language that lacks a text shows the English one.

This file is made from the texts of the library by a test. After a text changes, make it again with `LIMB_UPDATE_DOCS=1 go test ./internal/adminui -run TestTheTableOfTheTextsIsUpToDate`.

| Key | English | Русский |
| --- | --- | --- |
| `account.notice.password` | The password was changed. Every other session was ended. | Пароль изменён. Все остальные сеансы завершены. |
| `account.notice.session` | The session was ended. | Сеанс завершён. |
| `account.notice.sessions` | Every other session was ended. | Все остальные сеансы завершены. |
| `account.since` | The account was made on %s. | Учётная запись создана: %s. |
| `account.title` | Your account | Ваша учётная запись |
| `audit.action.admin.created` | Administrator created | Создан администратор |
| `audit.action.admin.deleted` | Administrator deleted | Удалён администратор |
| `audit.action.admin.disabled` | Administrator disabled | Администратор отключён |
| `audit.action.admin.enabled` | Administrator enabled | Администратор включён |
| `audit.action.admin.login` | Administrator signed in | Вход администратора |
| `audit.action.admin.login_failed` | Failed sign-in of an administrator | Неудачный вход администратора |
| `audit.action.admin.logout` | Administrator signed out | Выход администратора |
| `audit.action.admin.password_changed` | Administrator changed their password | Администратор сменил пароль |
| `audit.action.admin.password_reset` | Password of an administrator reset | Сброшен пароль администратора |
| `audit.action.admin.recovery_code_used` | Recovery code used | Использован резервный код |
| `audit.action.admin.recovery_codes_renewed` | Recovery codes renewed | Резервные коды выпущены заново |
| `audit.action.admin.session_ended` | Session of an administrator ended | Завершена сессия администратора |
| `audit.action.admin.sessions_ended` | Sessions of an administrator ended | Завершены сессии администратора |
| `audit.action.admin.totp_enrolled` | Authenticator bound | Привязан аутентификатор |
| `audit.action.admin.totp_rebound` | Authenticator replaced | Заменён аутентификатор |
| `audit.action.admin.totp_reset` | Authenticator of an administrator reset | Сброшен аутентификатор администратора |
| `audit.action.auth.channel_verified` | Address or phone number confirmed | Адрес или телефон подтверждён |
| `audit.action.auth.login` | Signed in | Вход |
| `audit.action.auth.login_failed` | Failed sign-in | Неудачный вход |
| `audit.action.auth.logout` | Signed out | Выход |
| `audit.action.auth.password_changed` | Password changed | Пароль изменён |
| `audit.action.auth.password_reset` | Password reset | Пароль сброшен |
| `audit.action.auth.refresh_token_reused` | Refresh token used again | Повторное использование refresh-токена |
| `audit.action.auth.session_ended` | Session ended | Сессия завершена |
| `audit.action.auth.user_created` | Account created | Учётная запись создана |
| `audit.action.setting.changed` | Setting changed | Изменена настройка |
| `audit.action.user.blocked` | User blocked | Пользователь заблокирован |
| `audit.action.user.created` | User created by an administrator | Пользователь создан администратором |
| `audit.action.user.deleted` | User deleted | Пользователь удалён |
| `audit.action.user.identifier_added` | Value to sign in with added | Добавлено значение для входа |
| `audit.action.user.identifier_changed` | Value to sign in with changed | Изменено значение для входа |
| `audit.action.user.identifier_removed` | Value to sign in with removed | Удалено значение для входа |
| `audit.action.user.identifier_verified` | Value marked as confirmed | Значение отмечено подтверждённым |
| `audit.action.user.invitation_resent` | Invitation sent again | Приглашение отправлено снова |
| `audit.action.user.invited` | User invited | Пользователь приглашён |
| `audit.action.user.password_reset_sent` | Link to reset the password sent | Отправлена ссылка для сброса пароля |
| `audit.action.user.password_temporary` | Temporary password set | Задан временный пароль |
| `audit.action.user.purged` | User removed for good | Пользователь удалён окончательно |
| `audit.action.user.restored` | User restored | Пользователь восстановлен |
| `audit.action.user.session_ended` | Session of the user ended | Завершена сессия пользователя |
| `audit.action.user.sessions_ended` | Sessions of the user ended | Завершены сессии пользователя |
| `audit.action.user.unblocked` | User unblocked | Пользователь разблокирован |
| `audit.actor.admin.gone` | deleted administrator %s | удалённый администратор %s |
| `audit.actor.api` | code of the application | код приложения |
| `audit.actor.cli` | command line | командная строка |
| `audit.actor.maintenance` | maintenance | обслуживание |
| `audit.actor.unknown` | unknown | неизвестно |
| `audit.actor.user` | the user | сам пользователь |
| `audit.col.address` | Address | Адрес |
| `audit.col.details` | Details | Подробности |
| `audit.col.time` | Time | Время |
| `audit.col.user` | User | Пользователь |
| `audit.col.what` | What | Что |
| `audit.col.who` | Who | Кто |
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
| `factor.left` | Recovery codes left: %d. | Осталось резервных кодов: %d. |
| `factor.rebind` | Bind another authenticator | Привязать другой аутентификатор |
| `factor.rebind.hint` | The old authenticator and the old recovery codes stop working, and every other session ends. | Прежний аутентификатор и прежние резервные коды перестанут действовать, а все остальные сеансы завершатся. |
| `factor.renew` | Make new recovery codes | Создать новые резервные коды |
| `factor.renew.hint` | The old recovery codes stop working. | Прежние резервные коды перестанут действовать. |
| `factor.title` | Authenticator and recovery codes | Аутентификатор и резервные коды |
| `home.account` | Your account | Ваша учётная запись |
| `home.account.text` | Change your password, bind another authenticator, make new recovery codes and see where you are signed in. | Смените пароль, привяжите другой аутентификатор, создайте новые резервные коды и посмотрите, где вы вошли. |
| `home.recovery` | You have %d recovery codes left. Make new ones on the page of your account. | Резервных кодов осталось: %d. Создайте новые на странице учётной записи. |
| `home.recovery.0` | You have no recovery codes left. Make new ones on the page of your account. | Резервных кодов не осталось. Создайте новые на странице учётной записи. |
| `home.signed.in` | You signed in at %s. | Вы вошли: %s. |
| `home.title` | Administration | Администрирование |
| `home.users` | Users | Пользователи |
| `home.users.text` | Find users, see their sessions and sign-ins, block and delete them, reset their passwords. | Найти пользователей, посмотреть их сеансы и входы, заблокировать и удалить, сбросить пароль. |
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
| `nav.users` | Users | Пользователи |
| `newuser.how` | How the user gets in | Как пользователь получит доступ |
| `newuser.invite.none` | Invitations need a sender of messages and the address of the page where the user chooses a password, which this service has not been given. | Для приглашений нужны отправка сообщений и адрес страницы, где пользователь выбирает пароль. У этого сервиса их нет. |
| `newuser.keep` | The user does not have to choose another password when they first sign in | Пользователю не нужно выбирать другой пароль при первом входе |
| `newuser.mode.invite` | By an invitation: they choose the password with a link that is sent to them | По приглашению: пароль он выберет по ссылке, которую ему отправят |
| `newuser.mode.password` | With a password that I give them | С паролем, который я ему дам |
| `newuser.password` | Password | Пароль |
| `newuser.submit` | Create the user | Создать пользователя |
| `newuser.title` | New user | Новый пользователь |
| `newuser.values` | What the user signs in with | Чем пользователь входит |
| `newuser.values.hint` | The same checks apply as when a user signs up. An address or a phone number can be marked as confirmed if you vouch for it, and the log says that you did. | Действуют те же проверки, что и при регистрации. Адрес или телефон можно отметить подтверждённым, если вы ручаетесь за него, и журнал это запишет. |
| `newuser.verified` | I vouch that it is theirs: mark it as confirmed | Ручаюсь, что это его значение: отметить подтверждённым |
| `password.again` | New password again | Новый пароль ещё раз |
| `password.current` | Current password | Текущий пароль |
| `password.differ` | The two new passwords are not the same. | Новые пароли не совпадают. |
| `password.hint` | When the password changes you stay signed in here and every other session ends. | После смены пароля вы остаётесь в этом сеансе, а все остальные завершаются. |
| `password.new` | New password | Новый пароль |
| `password.rule.common_password` | many people use it | его выбирают слишком многие |
| `password.rule.login_identifier` | it is the same as the login | он совпадает с логином |
| `password.rule.max_length` | it is too long | он слишком длинный |
| `password.rule.min_length` | it is too short | он слишком короткий |
| `password.rule.other` | it breaks a rule of the service | он нарушает правило сервиса |
| `password.rule.same_as_current` | it is the current password | он совпадает с текущим |
| `password.rules` | The new password is not allowed: %s. | Новый пароль не подходит: %s. |
| `password.submit` | Change the password | Сменить пароль |
| `password.title` | Change the password | Смена пароля |
| `password.wrong` | The current password is wrong. | Текущий пароль неверный. |
| `rebind.cancel` | Back to the account | Назад к учётной записи |
| `rebind.expired` | The binding has expired. Start again. | Время привязки истекло. Начните заново. |
| `rebind.intro` | Scan this QR code with the app that is to replace the old one. The old authenticator works until you confirm the new one. | Отсканируйте этот QR-код приложением, которое заменит прежнее. Прежний аутентификатор действует, пока вы не подтвердите новый. |
| `rebind.submit` | Confirm and replace | Подтвердить и заменить |
| `rebind.title` | Bind another authenticator | Привязка другого аутентификатора |
| `recovery.done` | I have saved them, continue | Я сохранил(а) их, продолжить |
| `recovery.intro` | Keep these codes in a safe place, apart from your phone. If you lose the authenticator, each of them lets you sign in once. They are shown only now. | Сохраните эти коды в надёжном месте, отдельно от телефона. Если вы потеряете аутентификатор, каждый из них позволит войти один раз. Они показываются только сейчас. |
| `recovery.list` | Recovery codes | Резервные коды |
| `recovery.title` | Your recovery codes | Ваши резервные коды |
| `session.kind.cookie` | cookie | cookie |
| `session.kind.token` | tokens | токены |
| `sessions.action` | Action | Действие |
| `sessions.address` | Address | Адрес |
| `sessions.browser` | Browser | Браузер |
| `sessions.caption` | Your sessions | Ваши сеансы |
| `sessions.current` | This session | Этот сеанс |
| `sessions.end` | End | Завершить |
| `sessions.end.others` | End every other session | Завершить все остальные сеансы |
| `sessions.none` | There is no other session. | Других сеансов нет. |
| `sessions.seen` | Last used | Последнее обращение |
| `sessions.started` | Signed in | Вход |
| `sessions.title` | Where you are signed in | Где вы вошли |
| `signed.in.as` | Signed in as %s | Вы вошли как %s |
| `skip` | Skip to the content | Перейти к содержимому |
| `status.active` | Active | Активен |
| `status.blocked` | Blocked | Заблокирован |
| `status.deleted` | Deleted | Удалён |
| `temporary.back` | Back to the user | Назад к пользователю |
| `temporary.for` | The temporary password of %s: | Временный пароль пользователя %s: |
| `temporary.text` | Give it to the user. It is shown only now and cannot be found again. All the sessions of the user ended, and they have to choose another password when they sign in. | Передайте его пользователю. Он показан только сейчас, потом его не найти. Все сессии пользователя завершены, а при входе ему придётся выбрать другой пароль. |
| `temporary.title` | Temporary password | Временный пароль |
| `time.utc` | %s UTC | %s UTC |
| `user.account` | Account | Учётная запись |
| `user.back` | ← All users | ← Все пользователи |
| `user.block.change` | Change the block | Изменить блокировку |
| `user.block.change.submit` | Change the block | Изменить блокировку |
| `user.block.hint` | A block ends all the sessions of the user at once, and the user cannot sign in until it is lifted or has run out. | Блокировка сразу завершает все сессии пользователя, и он не сможет войти, пока её не снимут или она не закончится. |
| `user.block.reason` | Reason | Причина |
| `user.block.submit` | Block | Заблокировать |
| `user.block.title` | Block the user | Заблокировать пользователя |
| `user.block.until` | Until (a day, UTC) | До (день, UTC) |
| `user.block.until.hint` | The block ends at 00:00 UTC on this day. Leave it empty for a block without an end. | Блокировка закончится в 00:00 UTC этого дня. Оставьте пустым, чтобы блокировка была бессрочной. |
| `user.blocked.forever` | never, until an administrator lifts it | никогда, пока её не снимет администратор |
| `user.blocked.noreason` | none given | не указана |
| `user.blocked.reason` | Reason of the block | Причина блокировки |
| `user.blocked.until` | The block ends | Блокировка закончится |
| `user.created` | Created | Создан |
| `user.delete.confirm` | To confirm, type a value that the user signs in with | Для подтверждения введите значение, которым пользователь входит |
| `user.delete.confirm.hint` | For example: %s | Например: %s |
| `user.delete.hint.immediate` | The account is erased at once, with its values, sessions and tokens. This cannot be undone. | Учётная запись стирается сразу вместе со значениями для входа, сессиями и токенами. Отменить это нельзя. |
| `user.delete.hint.soft` | The user cannot sign in any more and their sessions end, but the values they sign in with stay taken. An administrator can restore the account until the time of keeping runs out, and then it is removed for good. | Пользователь больше не сможет войти, его сессии завершатся, но значения, которыми он входил, останутся занятыми. Администратор может восстановить учётную запись, пока не истечёт срок хранения, потом она удаляется окончательно. |
| `user.delete.submit` | Delete the user | Удалить пользователя |
| `user.delete.title` | Delete the user | Удалить пользователя |
| `user.deleted.at` | Deleted | Удалён |
| `user.deleted.until` | Removed for good after | Будет удалён окончательно после |
| `user.error.busy` | The queue of messages is full. Try again in a moment. | Очередь сообщений заполнена. Повторите через минуту. |
| `user.error.changed` | The user kept changing meanwhile. Check the card and try again. | Пользователь менялся в это же время. Проверьте карточку и повторите. |
| `user.error.confirm` | What you typed is not a value that the user signs in with. | Введено не то значение, которым пользователь входит. |
| `user.error.deleted` | The user is deleted. | Пользователь удалён. |
| `user.error.haspassword` | The user has a password already, there is nothing to invite them to. | У пользователя уже есть пароль, приглашать его не к чему. |
| `user.error.identifier` | The value of %s is not accepted: %s. | Значение «%s» не принято: %s. |
| `user.error.invitations` | The service cannot send invitations. | Сервис не может отправлять приглашения. |
| `user.error.lastlogin` | A user has to keep at least one value to sign in with. | У пользователя должно остаться хотя бы одно значение для входа. |
| `user.error.noaddress` | The user has no address or phone number to send the invitation to. | У пользователя нет адреса или телефона, куда можно отправить приглашение. |
| `user.error.nochannel` | The user has no confirmed address or phone number to send the link to. Confirm a value, or set a temporary password. | У пользователя нет подтверждённого адреса или телефона, куда можно отправить ссылку. Подтвердите значение или задайте временный пароль. |
| `user.error.nosender` | The service has no way to send messages. | У сервиса нет способа отправлять сообщения. |
| `user.error.notdeleted` | The user is not deleted. | Пользователь не удалён. |
| `user.error.reason.invalid` | The reason has to be text without control characters, at most %d bytes. | Причина должна быть текстом без управляющих символов, не длиннее %d байт. |
| `user.error.reason.required` | Give the reason of the block. | Укажите причину блокировки. |
| `user.error.refused` | The application does not allow this user to be deleted. | Приложение не позволяет удалить этого пользователя. |
| `user.error.retention` | The time to restore the user has run out. | Время для восстановления пользователя истекло. |
| `user.error.taken` | Another user has this value. | Это значение уже есть у другого пользователя. |
| `user.error.temporary` | The checks of the application refused the password that was made. Try again. | Проверки приложения не приняли созданный пароль. Попробуйте ещё раз. |
| `user.error.until.invalid` | The day of the end of the block is not valid. | День окончания блокировки не подходит. |
| `user.error.until.past` | The day of the end of the block has to be in the future. | День окончания блокировки должен быть в будущем. |
| `user.id` | ID | ID |
| `user.ident.add` | Add a value | Добавить значение |
| `user.ident.add.submit` | Add | Добавить |
| `user.ident.confirm` | Mark as confirmed | Отметить подтверждённым |
| `user.ident.confirmed` | Confirmed | Подтверждено |
| `user.ident.new` | New value of the type %s | Новое значение типа %s |
| `user.ident.no` | not confirmed | не подтверждено |
| `user.ident.remove` | Remove | Удалить |
| `user.ident.save` | Save | Сохранить |
| `user.ident.type` | Type | Тип |
| `user.ident.value` | Value | Значение |
| `user.identifiers` | What the user signs in with | Чем пользователь входит |
| `user.identifiers.caption` | The values that the user signs in with | Значения, которыми пользователь входит |
| `user.identifiers.none` | The user has no value to sign in with. | У пользователя нет значений для входа. |
| `user.invite.hint` | The user was invited and has not chosen a password yet. Sending the invitation again ends the links that were sent before. | Пользователя пригласили, и он ещё не выбрал пароль. Повторная отправка прекращает действие ссылок, отправленных раньше. |
| `user.invite.submit` | Send the invitation again | Отправить приглашение ещё раз |
| `user.invite.title` | Invitation | Приглашение |
| `user.journal` | Changes | Изменения |
| `user.journal.caption` | What was changed about the user, and by whom | Что менялось у пользователя и кто это делал |
| `user.journal.none` | Nothing was changed yet. | Изменений пока не было. |
| `user.last` | Last sign-in | Последний вход |
| `user.must.change` | has to be changed at the next sign-in | нужно сменить при следующем входе |
| `user.notice.blocked` | The user is blocked and their sessions ended. | Пользователь заблокирован, его сессии завершены. |
| `user.notice.confirmed` | The value is marked as confirmed. | Значение отмечено подтверждённым. |
| `user.notice.created` | The user is created. | Пользователь создан. |
| `user.notice.deleted` | The user is deleted. | Пользователь удалён. |
| `user.notice.identifier` | The value is saved. | Значение сохранено. |
| `user.notice.invitation` | The invitation is being sent again. | Приглашение отправляется ещё раз. |
| `user.notice.invitebusy` | The user is created, but the invitation could not be queued now. Send it again from this card. | Пользователь создан, но приглашение сейчас не удалось поставить в очередь. Отправьте его ещё раз из этой карточки. |
| `user.notice.invited` | The user is created and the invitation is being sent. | Пользователь создан, приглашение отправляется. |
| `user.notice.link` | The link to choose a new password is being sent to the user. | Ссылка для выбора нового пароля отправляется пользователю. |
| `user.notice.removed` | The value is removed. | Значение удалено. |
| `user.notice.restored` | The user is restored. | Пользователь восстановлен. |
| `user.notice.session` | The session ended. | Сессия завершена. |
| `user.notice.sessions` | The sessions ended. | Сессии завершены. |
| `user.notice.unblocked` | The block is lifted. | Блокировка снята. |
| `user.password` | Password | Пароль |
| `user.password.none` | none yet, the user was invited and has not chosen one | ещё нет, пользователя пригласили, и он не выбрал пароль |
| `user.password.set` | set | задан |
| `user.reset.language` | Language of the message | Язык сообщения |
| `user.reset.link.hint` | Sends a link to the confirmed address or phone number of the user, where they choose a new password. | Отправляет на подтверждённый адрес или телефон пользователя ссылку, по которой он выберет новый пароль. |
| `user.reset.link.submit` | Send the link | Отправить ссылку |
| `user.reset.nosender` | The service has no way to send messages, so a link cannot be sent. | У сервиса нет способа отправлять сообщения, поэтому ссылку отправить нельзя. |
| `user.reset.temp.hint` | Makes a password that you give to the user yourself. All the sessions of the user end, and they have to choose another password when they sign in. | Создаёт пароль, который вы сами передаёте пользователю. Все сессии пользователя завершатся, а при входе ему придётся выбрать другой пароль. |
| `user.reset.temp.submit` | Set a temporary password | Задать временный пароль |
| `user.reset.title` | Reset the password | Сброс пароля |
| `user.restore.hint` | The user can sign in again. The sessions that ended are not restored. | Пользователь снова сможет войти. Завершённые сессии не восстанавливаются. |
| `user.restore.submit` | Restore | Восстановить |
| `user.restore.title` | Restore the user | Восстановить пользователя |
| `user.sessions` | Sessions in use | Сессии в работе |
| `user.sessions.caption` | The sessions of the user that are in use | Сессии пользователя, которые в работе |
| `user.sessions.end.all` | End all sessions | Завершить все сессии |
| `user.sessions.ends` | Ends | Закончится |
| `user.sessions.kind` | Kept by | Чем держится |
| `user.sessions.none` | The user has no session in use. | У пользователя нет сессий в работе. |
| `user.signins` | Sign-ins | Входы |
| `user.signins.caption` | The last sign-ins, failed attempts and sign-outs of the user | Последние входы, неудачные попытки и выходы пользователя |
| `user.signins.none` | Nobody signed in as this user yet. | Входов этого пользователя пока не было. |
| `user.status` | Status | Статус |
| `user.unblock` | Lift the block | Снять блокировку |
| `users.apply` | Apply | Применить |
| `users.caption` | The users of the service | Пользователи сервиса |
| `users.change` | has to change the password | должен сменить пароль |
| `users.col.created` | Created | Создан |
| `users.col.last` | Last sign-in | Последний вход |
| `users.col.login` | Signs in with | Вход по |
| `users.col.open` | Open | Открыть |
| `users.col.status` | Status | Статус |
| `users.col.via` | Origin | Происхождение |
| `users.confirmed` | Confirmed address or phone number | Подтверждённый адрес или телефон |
| `users.confirmed.any` | Does not matter | Не важно |
| `users.confirmed.mark` | confirmed | подтверждено |
| `users.confirmed.no` | Has none | Нет |
| `users.confirmed.yes` | Has one | Есть |
| `users.created.from` | Created from | Создан с |
| `users.created.to` | Created until | Создан по |
| `users.dir` | Direction | Порядок |
| `users.dir.asc` | Ascending | По возрастанию |
| `users.dir.desc` | Descending | По убыванию |
| `users.empty` | There are no users yet. | Пользователей пока нет. |
| `users.field.cursor` | the page | страница |
| `users.field.search` | the text to search for | текст для поиска |
| `users.filters` | Search and filters | Поиск и фильтры |
| `users.first` | First page | Первая страница |
| `users.invalid` | A value in the search is not valid: %s. | Значение в поиске не подходит: %s. |
| `users.limit` | On a page | На странице |
| `users.login.from` | Signed in from | Входил с |
| `users.login.to` | Signed in until | Входил по |
| `users.never` | Never signed in | Ни разу не входили |
| `users.never.signed` | never | никогда |
| `users.new` | New user | Новый пользователь |
| `users.next` | Next page | Следующая страница |
| `users.none` | Nobody matches. | Никто не подошёл. |
| `users.notice.erased` | The user is erased. | Пользователь стёрт. |
| `users.open` | Open | Открыть |
| `users.open.user` | Open the user %s | Открыть пользователя %s |
| `users.order` | Order by | Сортировать по |
| `users.order.created` | The time of creation | времени создания |
| `users.order.last` | The last sign-in | последнему входу |
| `users.order.status` | The status | статусу |
| `users.pages` | Pages of the list | Страницы списка |
| `users.reset` | Reset | Сбросить |
| `users.search` | Search by what they sign in with | Поиск по тому, чем входят |
| `users.search.hint` | Three characters or more find the values that start with them, fewer find exactly that value. | От трёх символов находятся значения, которые с них начинаются, короче — ровно такое значение. |
| `users.status` | Status | Статус |
| `users.title` | Users | Пользователи |
| `users.until` | until | до |
| `users.via` | Origin | Происхождение |
| `users.via.any` | Any origin | Любое |
| `via.admin` | Administrator | Администратор |
| `via.api` | Application code | Код приложения |
| `via.invite` | Invitation | Приглашение |
| `via.signup` | Sign-up | Регистрация |
