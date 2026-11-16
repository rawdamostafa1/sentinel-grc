# GRC service (assets, risks, KRIs, client portal data). Build: docker build -t sentinel-grc .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv/grc

COPY requirements-runtime.txt .
RUN pip install --no-cache-dir -r requirements-runtime.txt

COPY app ./app
COPY fixtures ./fixtures
COPY controls_data ./controls_data
COPY grc_client ./grc_client
COPY seed.py seed_all.py seed_controls.py seed_risks.py seed_incidents.py seed_findings.py seed_demo.py check_db.py ./

# the security rules of the project: containers do not run as root
RUN useradd --create-home --uid 10001 grc && chown -R grc /srv/grc
USER grc

EXPOSE 8001
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8001/health', timeout=2).status == 200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
