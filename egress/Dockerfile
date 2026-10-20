# tentaclAI egress gateway – forward proxy between the sandbox network and the outside
FROM python:3.15-slim-bookworm
ENV PYTHONUNBUFFERED=1
COPY egress/gw.py /app/gw.py
COPY lib/tclib.py lib/egress-default.txt /app/
COPY VERSION /app/VERSION
RUN useradd -r -u 10002 egress && mkdir /data && chown egress /data
USER egress
EXPOSE 3128
CMD ["python", "/app/gw.py"]
