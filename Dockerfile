FROM python:3.12-slim

# Flask is the only dependency.
RUN pip install --no-cache-dir flask==3.0.3

# The web application.
COPY app/ /app/

# The guided walkthrough + solution pages, served in-container at
# /solution.html and /sub-page.html (see the routes in app.py).
COPY Tutorial/ /app/tutorial/

# The flag lives OUTSIDE the app, at the container root. The whole challenge is
# to climb out of /app/data/reports and read this file via directory traversal:
#   /app/data/reports/../../../private_folder/flag.txt  ->  /private_folder/flag.txt
#
# It is dropped at BUILD TIME from a triple-encoded blob so the plaintext flag
# never sits in the source tree. The blob is  ROT47 -> base64 -> base32  of the
# flag; the step below reverses it (base32 -d -> base64 -d -> ROT47, which is
# self-inverse). This is obfuscation, NOT security: anyone reading these build
# steps can reverse it -- it just keeps the flag non-obvious at a glance.
# Override at build with:  docker build --build-arg FLAG_ENC=<blob> .
ARG FLAG_ENC="JZ5DA6KPIZ4GQYKHKZVU43KGNNGTEY32JYZE43SZNVUG4YKEKZXWCRCONNMW2TTOLEZESMCNNVHGUWKBN46Q===="
RUN mkdir -p /private_folder \
 && printf '%s' "$FLAG_ENC" | base32 -d | base64 -d | tr '!-~' 'P-~!-O' > /private_folder/flag.txt

WORKDIR /app
EXPOSE 8080

CMD ["python", "app.py"]
