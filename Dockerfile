FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/monitor3
RUN apt-get update && apt-get install --no-install-recommends -y iputils-ping \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system monitor3 && useradd --system --gid monitor3 monitor3
COPY pyproject.toml README.md ./
COPY src ./src
COPY config ./config
RUN pip install --no-cache-dir .
RUN mkdir -p /var/lib/monitor3 && chown monitor3:monitor3 /var/lib/monitor3
USER monitor3
EXPOSE 5001
CMD ["gunicorn", "--bind", "0.0.0.0:5001", "--workers", "2", "--threads", "4", "monitor.api.app:create_app()"]
