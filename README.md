# ICAP-сервер 

## Запуск локально:

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

