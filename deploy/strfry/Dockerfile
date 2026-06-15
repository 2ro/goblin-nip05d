# Builds the Goblin relay: strfry (https://github.com/hoytech/strfry) compiled
# from source at a pinned commit, plus python3 and the kind-allowlist write
# policy. docker-compose builds this as the `relay` service.
#
# Pinned for reproducibility — bump STRFRY_REF to update strfry.
FROM alpine:3.18 AS build
ENV TZ=Europe/London
WORKDIR /build
RUN apk --no-cache add \
        linux-headers git g++ make perl pkgconfig libtool ca-certificates \
        libressl-dev zlib-dev lmdb-dev flatbuffers-dev libsecp256k1-dev zstd-dev
ARG STRFRY_REF=7984f80822189bf8124699f3d49580334b32385e
RUN git clone https://github.com/hoytech/strfry . \
    && git checkout "${STRFRY_REF}" \
    && git submodule update --init \
    && make setup-golpe \
    && make -j"$(nproc)"

FROM alpine:3.18
WORKDIR /app
RUN apk --no-cache add \
        lmdb flatbuffers libsecp256k1 libb2 zstd libressl python3 \
    && rm -rf /var/cache/apk/*
COPY --from=build /build/strfry /app/strfry
COPY strfry-writepolicy.py /usr/local/bin/strfry-writepolicy.py
RUN chmod +x /usr/local/bin/strfry-writepolicy.py && mkdir -p /strfry-db
EXPOSE 7777
ENTRYPOINT ["/app/strfry"]
CMD ["relay"]
