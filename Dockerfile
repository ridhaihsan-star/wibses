FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py sk_wib.py sk_ses.py docx_sk.py kta_card.py ./
COPY referensi/ ./referensi/
COPY static/ ./static/
COPY assets/ ./assets/
ENV WIB_DATA_DIR=/appdata WIB_SEED_DEMO=0
VOLUME ["/appdata"]
EXPOSE 8765
CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8765","--proxy-headers=false"]
