FROM debian:stable-slim

LABEL version="1.1.1"

RUN useradd -r BitcoinDiamond \
  && apt-get update -y \
  && apt-get install -y curl gnupg \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
  && set -ex \
  && for key in \
    B42F6819007F00F88E364FD4036A9C25BF357DD4 \
  ; do \
    gpg --keyserver pgp.mit.edu --recv-keys "$key" || \
    gpg --keyserver keyserver.pgp.com --recv-keys "$key" || \
    gpg --keyserver ha.pool.sks-keyservers.net --recv-keys "$key" || \
    gpg --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys "$key" ; \
  done

ENV GOSU_VERSION=1.10

RUN curl -o /usr/local/bin/gosu -fSL https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-$(dpkg --print-architecture) \
  && curl -o /usr/local/bin/gosu.asc -fSL https://github.com/tianon/gosu/releases/download/${GOSU_VERSION}/gosu-$(dpkg --print-architecture).asc \
  && gpg --verify /usr/local/bin/gosu.asc \
  && rm /usr/local/bin/gosu.asc \
  && chmod +x /usr/local/bin/gosu

ENV BITCOINDIAMOND_VERSION=1.1.1
ENV BITCOINDIAMOND_DATA=/home/BitcoinDiamond/.bitcoindiamond
ENV PATH=/opt/bitcoindiamond-${BITCOINDIAMOND_VERSION}/bin:$PATH

COPY docker-entrypoint.sh /entrypoint.sh

RUN curl -SLO https://github.com/eveybcd/BitcoinDiamond/releases/download/v${BITCOINDIAMOND_VERSION}/bitcoindiamond-${BITCOINDIAMOND_VERSION}-x86_64-linux-gnu.tar.gz \
  && tar -xzf *.tar.gz -C /opt \
  && rm *.tar.gz \
  && chmod +x /entrypoint.sh

VOLUME ["/home/BitcoinDiamond/.bitcoindiamond"]

ENV UPNP=-1

EXPOSE 7116 7117 18332 18333 18443 18444

ENTRYPOINT ["/entrypoint.sh"]

CMD ["bitcoindiamondd"]
