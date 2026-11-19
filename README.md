# ICAP-сервер 

## Запуск

Для локального запуска понадобится Python 3.12 и выше.
### Windows (PowerShell):
```
    git clone https://github.com/JunglePudge/test-tast-pt.git
    cd .\test-task-pt
    cp .env.example .env
    python -m venv venv
    .\venv\Scripts\activate
    pip install -r requirements.txt
    python icap_server.py
```

### Запуск тестов
```
    git clone https://github.com/JunglePudge/test-tast-pt.git
    cd .\test-task-pt
    cp .env.example .env
    python -m venv venv
    .\venv\Scripts\activate
    pip install -r requirements.txt
    pytest
```

### Запуск из докера
```
    git clone https://github.com/JunglePudge/test-tast-pt.git
    cd .\test-task-pt
    docker build -t icap-respmod .
    docker run --rm -p 1344:1344 icap-respmod
    docker run --rm -p 1344:1344 --env-file .env icap-respmod     # запуск с ключом из .env
```
