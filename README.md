##Описание проекта

Этот проект представляет собой простой сайт-визитку преподавателя-программиста Ивана Иванова. Сайт создан с использованием фреймворка Flask и HTML-шаблонов. На сайте можно найти основную информацию о преподавателе, а также записаться на курс программирования.

##Структура проекта

Проект состоит из следующих файлов и директорий:

- app.py: Главный файл приложения, который запускает сервер Flask и определяет маршруты.
templates/

- base.html: Базовый HTML-шаблон, который содержит общую структуру страницы.

- index.html: Шаблон главной страницы сайта.

- about.html: Шаблон страницы записи на курс.

- payment.html: Шаблон страницы оплаты (в разработке, тут можно подключить запись).
static/css/

- main.css: Основной файл стилей для сайта.

##Установка и запуск

Для запуска проекта выполните следующие шаги:

1. Клонируйте репозиторий:

2. Создайте виртуальное окружение и активируйте его:

python -m venv venv
source venv/bin/activate  # На Windows используйте `venv\Scripts\activate`

3. Установите необходимые зависимости:

pip install Flask

4. Запустите сервер:

python app.py

5. Откройте браузер и перейдите по адресу:

http://127.0.0.1:5000/


##Описание файлов

Файл app.py содержит основные маршруты для сайта:

/ и /index: главная страница.
/about: страница записи на курс.

Шаблоны

- base.html: Базовый шаблон, содержащий общую структуру HTML-документа.

- index.html: Шаблон главной страницы.

- about.html: Шаблон страницы записи на курс.


##Стили

- Файл main.css содержит стили для всех страниц сайта.

##Дополнительная информация

Проект можно расширить, добавив дополнительные страницы, улучшив стилизацию и добавив функционал для обработки записей на курс и оплаты.



### Добавленные файлы:

1. **cards.html:**  
   - Создан HTML-файл для отображения карточек.
   - Использует шаблон Flask и подключает файл стилей `cards.css`.

2. **cards_html.html:**  
   - Расширяет базовый шаблон `cards.html`.
   - Содержит разметку и стили для отображения карточек городов.

3. **cards.css:**  
   - Создан файл стилей для карточек.
   - Определяет стили для основной оболочки, заголовка, карточек и их содержимого.

4. **reg.css:**  
   - Добавлен файл стилей для страниц регистрации и входа.
   - Определяет стили для форм, полей ввода, кнопок и ссылок.

### Измененные файлы:

5. **login.html:**  
   - Добавлены HTML и Jinja2-шаблоны для страницы входа.
   - Использует базовый шаблон `registGL.html`.

6. **register.html:**  
   - Добавлены HTML и Jinja2-шаблоны для страницы регистрации.
   - Использует базовый шаблон `registGL.html`.

7. **registGL.html:**  
   - Добавлен Jinja2-шаблон, расширяемый другими страницами.
   - Подключает файл стилей `reg.css` и иконочный шрифт Boxicons.

### Измененный файл:

8. **app.py:**  
   - Добавлен маршрут для отображения страницы с карточками (`/cards`).
   - Обновлены импорты и функции маршрутов для работы с новыми страницами.
   - Инициализация базы данных происходит при запуске приложения.






