FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY icap_server.py .

ENV ICAP_AES_KEY_HEX=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
    ICAP_HOST=0.0.0.0 \
    ICAP_PORT=1344

EXPOSE 1344
CMD ["python", "icap_server.py"]