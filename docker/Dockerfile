FROM alpine:latest as tor-build-stage

# Install prerequisites
RUN apk --no-cache add --update \
        gnupg \
        build-base \
        libevent \
        libevent-dev \
        libressl \
        libressl-dev \
        xz-libs \
        xz-dev \
        zlib \
        zlib-dev \
        zstd \
        zstd-dev \
      && wget -q https://dist.torproject.org/tor-0.4.6.6.tar.gz \
      && tar xf tor-0.4.6.6.tar.gz \
      && cd tor-0.4.6.6 \
      && ./configure \
      && make install \
      && ls -R /usr/local/

#-----------------------------------------------
# Build CWTCH
#-----------------------------------------------

FROM golang:alpine as cwtch-build-stage
RUN apk --no-cache add --update gcc build-base
COPY . src/
RUN cd src/app && go build 


FROM alpine:latest
#BSD habits die hard
ENV TOR_USER=_tor CWTCH_USER=_cwtch

# Installing dependencies of Tor and pwgen
RUN apk --no-cache add --update \
      libevent \
      libressl \
      xz-libs \
      zlib \
      zstd \
      zstd-dev \
      pwgen

# Copy Tor
COPY --from=tor-build-stage /usr/local/ /usr/local/

#Copy cwtch app
COPY --from=cwtch-build-stage /go/src/app/app /usr/local/bin/cwtch

# Create an unprivileged tor user
RUN mkdir -p /run/tor && mkdir /etc/cwtch && addgroup -S $TOR_USER && adduser -G $TOR_USER -S $TOR_USER && adduser -S $CWTCH_USER

# Copy Tor configuration file
COPY ./docker/torrc /etc/tor/torrc

# Copy docker-entrypoint
COPY ./docker/docker-entrypoint /usr/local/bin/

# Persist data
VOLUME /etc/tor /var/lib/tor /etc/cwtch

ENTRYPOINT ["docker-entrypoint"]
#USER $CWTCH_USER
CMD ["/usr/local/bin/cwtch"]

