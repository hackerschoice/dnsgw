FROM golang:1.22.1-bullseye as builder
RUN apt-get update && apt-get install -y git autoconf patch
WORKDIR /app
COPY . .
RUN go build -o dnsgw .
RUN git clone https://github.com/alex-sector/dns2tcp /dns2tcpd

RUN curl -sL https://gist.githubusercontent.com/al3x8/c6a99858d7f692896ea20e9d01eb0412/raw/bf2ca61d610e8af2c91a611706a4733932d23e48/dns2tcpd.patch | patch -d /dns2tcpd -p1

RUN cd /dns2tcpd && \
    ./configure && \
    make && \
    make install

FROM debian:bullseye-slim

COPY --from=builder /app/dnsgw .
COPY --from=builder /usr/local/bin/dns2tcpd /usr/local/bin/dns2tcpd

# - 53 for DNS
# - 80 for HTTP
EXPOSE 53 80

CMD ["./dnsgw"]
