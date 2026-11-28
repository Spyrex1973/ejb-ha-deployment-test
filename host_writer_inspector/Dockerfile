FROM python:3.13-alpine
COPY inspect.py /opt/inspector.py
USER 65534:65534
CMD ["python", "-I", "-B", "-u", "/opt/inspector.py"]
