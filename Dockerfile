ARG PYTHON_BASE=python:3.12-alpine
FROM ${PYTHON_BASE}

# Apply the available Alpine zlib fix; allow non-Alpine comparison builds too.
RUN if command -v apk >/dev/null; then apk upgrade --no-cache zlib; fi

WORKDIR /app
COPY app/requirements.txt .
# Use a patched installer during the build, then remove it and its bundled
# libraries from the runtime filesystem after application installation.
RUN python -m pip install --no-cache-dir --upgrade pip==26.2.2 \
    && python -m pip install --no-cache-dir -r requirements.txt \
    && python -m pip uninstall --yes pip

COPY app/app.py . 

# Set environment variables it can be changed during runtime if needed
ENV FLASK_APP=app.py \    
    PORT=5000 \
    DB_PATH=/app/users.db

EXPOSE 5000
CMD ["python", "app.py"]
