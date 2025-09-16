FROM python:3-slim-trixie

RUN apt-get update && \
    apt-get install --assume-yes --no-install-recommends libzbar0

WORKDIR /app

COPY . .

RUN chmod +x *.sh *.py

RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT ["/bin/sh", "-c"]

CMD ["./usage_example.sh"]