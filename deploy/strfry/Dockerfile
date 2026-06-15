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
# PYTHONUNBUFFERED keeps the write-policy plugin's stdio prompt — it also flushes
# explicitly, so this is belt-and-suspenders against any buffering stall.
ENV PYTHONUNBUFFERED=1
RUN apk --no-cache add \
        lmdb flatbuffers libsecp256k1 libb2 zstd libressl python3 \
    && rm -rf /var/cache/apk/*
COPY --from=build /build/strfry /app/strfry
COPY strfry-writepolicy.py /usr/local/bin/strfry-writepolicy.py
# Run as a fixed non-root uid (not root): the relay takes untrusted network
# input, so drop privilege. Only the db dir needs to be owned by that uid (the
# binary/plugin are world-readable+executable already); a named volume inherits
# this ownership, and a bind mount must be chowned to 10001 on the host.
RUN addgroup -g 10001 -S strfry \
    && adduser -u 10001 -S -G strfry strfry \
    && chmod +x /usr/local/bin/strfry-writepolicy.py \
    && mkdir -p /strfry-db \
    && chown -R strfry:strfry /strfry-db
USER strfry
EXPOSE 7777
ENTRYPOINT ["/app/strfry"]
CMD ["relay"]
