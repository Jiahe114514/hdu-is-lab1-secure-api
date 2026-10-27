# Slim, non-root runtime image for the secure API.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000

WORKDIR /srv/app

# A dedicated unprivileged account limits the blast radius of a compromise.
RUN groupadd --system app && useradd --system --gid app --create-home app

COPY requirements.txt ./
RUN pip install --no-cache-dir --no-compile -r requirements.txt

COPY app ./app
COPY run.py ./

RUN mkdir -p /srv/app/instance && chown -R app:app /srv/app

USER app
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health')"

CMD ["python", "run.py"]
