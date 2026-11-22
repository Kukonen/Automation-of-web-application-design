# Повторная независимая проверка исправлений

Дата: 15.11.2026. Проверяющий: независимый агент аудита Codex. Проверены текущие файлы после исправлений. Код CMS и тесты проверяющий не изменял; создан только этот протокол. Использовались временные SQLite-базы и искусственные секреты.

## Статусы четырёх исправлений

| Исправление | Результат текущей проверки |
| --- | --- |
| Проверка прав при чтении через CMS.get | Подтверждено. Без actor чтение служебного материала запрещено; автор не читает чужой черновик; владелец читает свой; public=True скрывает черновик. Два адресных теста и отдельный сценарий прошли. |
| Явная передача actor из веб-слоя | Подтверждено прямыми WSGI-запросами. Вход автора, чтение своего редактора, сохранение и отправка на модерацию работают; чужой редактор возвращает 403; после модерации выполняется корректный переход в /admin. |
| Запрет секретов в guard | Регистронезависимые .ENV и .ENV.local блокируются; обычный файл разрешён. Исходный код проверяет как requested.parts, так и части разрешённого конечного пути. Практический тест внутренней символической ссылки пропущен: Windows не разрешает её создание в этой среде. Этот случай подтверждён чтением кода, но не успешным выполнением теста. |
| Единый предел description | Подтверждено. В реально отрендеренной форме maxlength=300; сохранение 300 символов успешно, запрос с 301 символом получает 400. |

Адресный unittest-прогон: 11 тестов, 10 прошли, 1 пропущен, ошибок и провалов нет. Это повторная проверка перечисленных исправлений, а не полный релизный прогон.

## Команды и сценарии

Рабочая папка всех команд: `C:\Users\EVGENNIY\Desktop\магистратура\Автоматизация проектирования интернет-приложений\cms`.

Выполненная команда адресных тестов:

```powershell
@'
import sys,unittest
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0,'tests')
names=['test_core.CoreTests.test_39_anonymous_service_get_and_list_are_denied','test_core.CoreTests.test_40_author_cannot_read_foreign_draft_via_service','test_harness.GuardTests']
suite=unittest.defaultTestLoader.loadTestsFromNames(names)
result=unittest.TextTestRunner(verbosity=2).run(suite)
sys.exit(not result.wasSuccessful())
'@ | & 'C:\Program Files\WindowsApps\OpenAI.CodexPrimaryRuntime.v26-1111-570-0_26.1111.570.0_x64__3k8sg7r9htsxt\dependencies\python\python.exe' -
```

Результат: `Ran 11 tests ... OK (skipped=1)`. Пропущен только `test_secret_symlink_denied` с причиной `Creating symlinks is unavailable in this Windows environment`.

Выполненный сценарий через WSGI без сетевых сокетов:

```powershell
@'
import sys,io,tempfile,re
from pathlib import Path
from urllib.parse import urlencode
from core import CMS
from web import WebApp
sys.stdout.reconfigure(encoding='utf-8')
with tempfile.TemporaryDirectory() as tmp:
 cms=CMS(tmp)
 admin=cms.create_user('admin','Review-Only-2026!','admin')
 author=cms.create_user('author','Review-Only-2026!','author',admin)
 data={'type':'news','title':'Review','slug':'review','body':'Body','fields':{'lead':'Lead'},'description':'x'*300,'category':'Review'}
 item=cms.create(data,author)
 foreign=cms.create(data|{'slug':'foreign'},admin)
 for actor in [None,author]:
  try:
   cms.get(foreign['id'],actor=actor)
  except PermissionError:
   pass
  else:
   raise AssertionError('Foreign draft disclosed')
 assert cms.get(item['id'],actor=author)['title']=='Review'
 assert cms.get(item['id'],public=True) is None
 print('SERVICE: anonymous and foreign author denied; owner allowed; public draft hidden')
 app=WebApp(cms,Path.cwd())
 def request(path,method='GET',form=None,cookies=''):
  route,_,query=path.partition('?')
  body=urlencode(form or {}).encode()
  captured={}
  env={'REQUEST_METHOD':method,'PATH_INFO':route,'QUERY_STRING':query,'HTTP_COOKIE':cookies,'CONTENT_TYPE':'application/x-www-form-urlencoded','CONTENT_LENGTH':str(len(body)),'wsgi.input':io.BytesIO(body)}
  payload=app(env,lambda status,headers:captured.update(status=status,headers=headers))
  captured['body']=b''.join(payload).decode()
  return captured
 first=request('/login')
 csrf_cookie=next(v.split(';')[0] for k,v in first['headers'] if k=='Set-Cookie' and v.startswith('cms_csrf='))
 csrf=csrf_cookie.split('=',1)[1]
 login=request('/login','POST',{'csrf':csrf,'username':'author','password':'Review-Only-2026!'},csrf_cookie)
 assert login['status']=='302 Found'
 session=next(v.split(';')[0] for k,v in login['headers'] if k=='Set-Cookie' and v.startswith('cms_session='))
 cookies=csrf_cookie+'; '+session
 page=request('/admin/edit/'+str(item['id']),cookies=cookies)
 assert page['status']=='200 OK'
 assert re.search(r'<textarea[^>]*name="description"[^>]*maxlength="300"',page['body'])
 assert request('/admin/edit/'+str(foreign['id']),cookies=cookies)['status']=='403 Forbidden'
 form={'csrf':csrf,'title':'Review','slug':'review','body':'Body','description':'x'*300,'category':'Review','tags':'','field_lead':'Lead'}
 assert request('/admin/edit/'+str(item['id']),'POST',form,cookies)['status']=='302 Found'
 assert len(cms.get(item['id'],actor=author)['description'])==300
 assert request('/admin/edit/'+str(item['id']),'POST',form|{'description':'x'*301},cookies)['status']=='400 Bad Request'
 transition=request('/admin/transition/'+str(item['id']),'POST',{'csrf':csrf,'status':'review'},cookies)
 assert transition['status']=='302 Found'
 assert ('Location','/admin') in transition['headers']
 assert cms.get(item['id'],actor=author)['status']=='review'
 print('WSGI: login/edit/update/review redirect work with explicit actor; foreign edit 403')
 print('DESCRIPTION: rendered maxlength=300; 300 accepted; 301 rejected without mutation')
 cms.close()
'@ | & 'C:\Program Files\WindowsApps\OpenAI.CodexPrimaryRuntime.v26-1111-570-0_26.1111.570.0_x64__3k8sg7r9htsxt\dependencies\python\python.exe' -
```

Результат: код возврата 0, все утверждения сценария выполнены, выведены три строки SERVICE, WSGI и DESCRIPTION.

## Ограничения и неуспешные попытки запуска

До успешного адресного прогона проверяющий ошибочно указал класс `test_web.WebTests`, которого нет; unittest сообщил три ошибки загрузки. Правильное имя класса — `test_web.HTTPTests`. Это ошибка запуска проверки, не дефект CMS.

После исправления имени была предпринята попытка выполнить `test_web.HTTPTests.test_02_http_crud_publish_restore_audit`, `test_web.HTTPTests.test_03_role_route_matrix` и `test_web.HTTPTests.test_08_http_author_cannot_publish_or_edit_others` тем же unittest-загрузчиком. Подключение urllib к локальному HTTP-серверу блокировалось средой с `PermissionError: [WinError 10013]`. Этот запуск не объявляется успешным. Указанный выше сценарий проверяет WSGI-маршруты напрямую и не подменяет проверку сетевого транспорта.

Полный HTTP-прогон в разрешённой среде, полный релизный прогон и визуальную проверку отчётов выполняет основной агент; результаты этих действий в настоящий протокол не включены.
