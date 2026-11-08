# Примеры политик open-appsec (v1beta2)

`default.yaml`, `example.yaml`, `prevent.yaml` — файлы `config/linux/v1beta2/<имя>/local_policy.yaml` из
[openappsec/openappsec](https://github.com/openappsec/openappsec) (коммит `OPENAPPSEC_REF` в
`deploy/openappsec/sources.env`), лицензия Apache 2.0.

Нужны тестам: `objects.test.js` проверяет, что их объекты проходят схему, а smoke-тест (`deploy/test/smoke.sh`)
импортирует `example.yaml` через API. При обновлении open-appsec скопируйте их заново из его репозитория.
