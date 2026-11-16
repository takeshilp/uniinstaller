// Every Russian UI string lives here. Rust sends codes; this file maps them to text.
// Badge wording: switching to SAFE / YOUR CALL is one edit (badgeSafe, badgeCall).

export function plural(n, [one, few, many]) {
  const a = Math.abs(n) % 100, b = a % 10;
  if (a > 10 && a < 20) return many;
  if (b > 1 && b < 5) return few;
  if (b === 1) return one;
  return many;
}

export const S = {
  appName: 'Uniinstaller',
  sandboxPill: 'ПЕСОЧНИЦА',
  adminPill: 'АДМИНИСТРАТОР',
  badgeSafe: 'НАДЁЖНО',
  badgeCall: 'НА ВАШ ВЫБОР',

  // settings popover
  settings: 'Настройки',
  version: 'Версия',
  rights: 'Права',
  rightsAdmin: 'администратор',
  rightsUser: 'обычный пользователь',
  sandboxPath: 'Песочница',
  dataFolder: 'Папка данных',
  checkUpdates: 'Проверить обновления',
  upToDate: 'Установлена последняя версия',
  updateCheckFailed: 'Не удалось проверить обновления',

  // update banner
  updateAvailable: (v) => `Доступна версия ${v}`,
  updateNow: 'Обновить',
  later: 'Позже',
  updating: 'Скачиваем обновление…',

  // programs
  homeTitle: 'Что удалим?',
  homeSub: 'Программы из реестра Windows. Ничего не удаляется без вашего подтверждения.',
  tabPrograms: 'Программы',
  tabHistory: 'История',
  searchPlaceholder: 'Найти программу',
  found: (n) => `Найдено ${n} ${plural(n, ['программа', 'программы', 'программ'])}`,
  loadingRegistry: 'Читаем реестр…',
  retry: 'Повторить',
  nothingFound: 'Ничего не найдено.',
  forAll: 'ДЛЯ ВСЕХ',
  onlyMe: 'ТОЛЬКО ДЛЯ МЕНЯ',
  loadError: 'Не удалось прочитать список программ',

  // card
  allPrograms: 'Все программы',
  perMachineWarn: 'Программа установлена для всех пользователей: её файлы лежат в Program Files, а записи в HKLM. Для удаления могут понадобиться права администратора.',
  restartAdmin: 'Перезапустить от имени администратора',
  restartSandboxNo: 'В песочнице перезапуск недоступен',
  details: 'Сведения',
  kId: 'Идентификатор',
  kProduct: 'Код продукта',
  kSources: 'Источники',
  kDir: 'Папка установки',
  kIcon: 'Значок',
  kUninstall: 'Команда удаления',
  kWillRun: 'Будет запущено',
  kQuiet: 'Тихая команда',
  kQuietUnused: 'не используется',
  kDate: 'Дата установки',
  kSize: 'Размер',
  unknown: 'неизвестно',
  launchErrorTitle: 'Деинсталлятор не удаётся запустить',
  sizeEstimate: 'Оценка размера',
  previewLeftovers: 'Предпросмотр остатков',
  runUninstaller: 'Запустить деинсталлятор',
  showInFolder: 'Показать в папке',

  // confirm
  confirmTitle: (name) => `Запустить деинсталлятор «${name}»?`,
  willRun: 'Будет запущено:',
  confirmNote: 'Некоторые деинсталляторы удаляют программу сразу, без собственных вопросов. Остатки мы покажем потом — до вашего подтверждения ничего не удаляется.',
  cancel: 'Отмена',
  run: 'Запустить',

  // running
  waitingTitle: 'Ждём деинсталлятор',
  waitingSub: 'Пройдите шаги в его окне. Мы дождёмся завершения всех его процессов.',
  waitingProcs: 'Ждём процессы:',
  stopWaiting: 'Не ждать дальше',
  stopNote: 'Ничего не будет закрыто.',

  // outcome
  outStillInstalled: 'Программа всё ещё установлена',
  outReboot: 'Нужна перезагрузка',
  outRebootSub: 'Остатки можно найти после перезагрузки в Истории.',
  outNotStarted: 'Деинсталлятор не запустился',
  outTimeout: 'Деинсталлятор не закончил работу за 60 минут',
  outRunning: 'Деинсталлятор ещё может работать',
  exitCode: (c) => `Код выхода: ${c}`,
  toPrograms: 'К списку программ',

  // review
  removedEyebrow: (name, code) => `${name} удалена · код выхода ${code ?? '—'}`,
  previewEyebrow: 'Предпросмотр · программа ещё установлена, ничего не изменится',
  leftovers: 'остатков',
  reviewSub: 'Отмечено только то, что точно принадлежало программе. Остальное — на ваше усмотрение.',
  exportJson: 'Экспорт JSON',
  exportReport: 'Экспорт отчёта',
  openFolder: 'Открыть папку',
  noLeftovers: 'Остатков не нашли.',
  done: 'Готово',
  selected: 'Выбрано',
  registryRecords: (n) => `${n} ${plural(n, ['запись реестра', 'записи реестра', 'записей реестра'])}`,
  scanAgain: 'Сканировать снова',
  back: 'Назад',
  deleteSelected: 'Удалить выбранное',
  weakMatch: 'слабое совпадение',
  score: (n) => `балл ${n}`,
  blocked: (why) => `Заблокировано: ${why}`,
  stillRunning: (names) => `Ещё работают: ${names}. Если это деинсталлятор — дождитесь его завершения и нажмите «Сканировать снова».`,
  dirRejected: (why) => `Папка установки отклонена: ${why}. Файлы программы не предлагаются.`,
  dirNotSet: 'Папка установки неизвестна: файлы программы не предлагаются.',

  groups: {
    programFiles: ['Файлы программы', 'Файлы и папки из папки установки и значок программы.'],
    shortcuts: ['Ярлыки', 'Ярлыки в меню «Пуск» и на рабочем столе, которые вели в программу.'],
    registry: ['Записи реестра', 'Автозапуск, пути запуска и запись об установке.'],
    data: ['Настройки и данные', 'Папки и ключи с настройками. Там могут быть ваши данные, поэтому они не отмечены.'],
  },
  groupIcon: { programFiles: '', shortcuts: '', registry: '', data: '' },

  evidence: {
    inInstallDir: 'внутри папки установки',
    installDirCorroborated: 'папка подтверждена деинсталлятором или значком',
    refersToInstallDir: 'ссылается на папку установки',
    targetMissing: 'цель больше не существует',
    ownUninstallEntry: 'собственная запись об установке',
    exactAnchor: 'значок программы',
    exactName: 'имя совпадает с программой',
    publisherMatch: 'совпадает издатель',
    userDataLikely: 'похоже на ваши данные',
    outsideKnownZones: 'вне Program Files и AppData',
  },
  blockCode: {
    protectedPath: 'защищённый путь',
    outsideAllowedZone: 'вне разрешённых мест',
    nonCanonicalPath: 'путь через псевдоним или короткое имя',
    sharedWithOtherApp: 'нужно другой программе',
    appStillInstalled: 'программа ещё установлена',
    protectedRegistry: 'защищённый раздел реестра',
    tooLarge: 'слишком большой',
    unverifiable: 'проверить не удалось',
    otherVolume: 'другой диск: резервная копия пока не поддерживается',
  },

  // result
  resultEyebrow: (name, date) => `${name} · ${date}`,
  opStatus: {
    running: 'Идёт удаление',
    awaitingReview: 'Ждёт проверки остатков',
    completed: 'Готово',
    completedWithWarnings: 'Готово с замечаниями',
    pendingReboot: 'Нужна перезагрузка',
    partiallyCompleted: 'Сделано частично',
    failed: 'Не удалось',
    restored: 'Восстановлено',
    partiallyRestored: 'Восстановлено частично',
  },
  opStatusPill: {
    running: ['muted', 'ИДЁТ'],
    awaitingReview: ['warn', 'ЖДЁТ ПРОВЕРКИ'],
    completed: ['accent', 'ГОТОВО'],
    completedWithWarnings: ['warn', 'С ЗАМЕЧАНИЯМИ'],
    pendingReboot: ['warn', 'ПЕРЕЗАГРУЗКА'],
    partiallyCompleted: ['warn', 'ЧАСТИЧНО'],
    failed: ['danger', 'ОШИБКА'],
    restored: ['muted', 'ВОССТАНОВЛЕНО'],
    partiallyRestored: ['warn', 'ЧАСТИЧНО ВОССТАНОВЛЕНО'],
  },
  itemStatus: {
    removed: ['accent', 'УБРАНО'],
    notFound: ['muted', 'УЖЕ НЕТ'],
    changed: ['warn', 'ИЗМЕНИЛОСЬ'],
    blocked: ['danger', 'ЗАПРЕЩЕНО'],
    accessDenied: ['warn', 'НЕТ ПРАВ'],
    locked: ['warn', 'ЗАНЯТО'],
    failed: ['danger', 'ОШИБКА'],
    inProgress: ['warn', 'НЕ ЗАВЕРШЕНО'],
  },
  restoreStatus: {
    restored: ['accent', 'ВОССТАНОВЛЕНО'],
    conflict: ['warn', 'КОНФЛИКТ'],
    missing: ['muted', 'НЕТ ДАННЫХ'],
    failed: ['danger', 'ОШИБКА'],
  },
  verification: 'Проверка',
  verifyGone: 'Программы больше нет в списке установленных.',
  verifyListed: 'Программа всё ещё есть в списке установленных.',
  verifyClean: 'Ничего из удалённого не появилось снова.',
  verifyReappeared: (n) => `Снова появилось: ${n}.`,
  resultCounts: (removed, total) => `Убрано ${removed} из ${total}`,
  deniedStrip: 'Часть объектов требует прав администратора. Перезапустите приложение от имени администратора, затем История → эта операция → Повторить.',
  canRestore: (n) => `Можно вернуть: ${n}`,
  restoreAll: 'Восстановить всё',
  retryFailed: 'Повторить',
  searchLeftovers: 'Искать остатки',

  // history
  historyTitle: 'История',
  historySub: 'Каждая операция хранит резервные копии — их можно вернуть.',
  historyEmpty: 'Пока пусто.',
  broken: 'ПОВРЕЖДЕНО',
  objects: (n) => `${n} ${plural(n, ['объект', 'объекта', 'объектов'])}`,

  busy: 'Выполняется операция…',
  error: 'Ошибка',
  sizeUnits: ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'],
};
