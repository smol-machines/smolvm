FROM alpine:3.19

WORKDIR /app

COPY hello.txt /app/hello.txt

# Simple custom startup logic: print a banner, show the local file,
# and report its size.
CMD ["sh", "-c", "echo 'Starting demo container'; echo '--- hello.txt ---'; cat /app/hello.txt; echo '-----------------'; echo \"Bytes: $(wc -c < /app/hello.txt)\""]
