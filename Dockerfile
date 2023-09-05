FROM python:3.11.4-alpine

WORKDIR /app/wordlists

COPY subdomains-top1million-110000.txt /app/wordlists/

WORKDIR /app

COPY esirp.py requirements.txt /app/

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["python", "esirp.py"]

CMD ["-h"]