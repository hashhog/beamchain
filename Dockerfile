# ---------- runtime ----------
# The release is pre-built by the CI runner (which has full internet access
# for fetching the rocksdb git dependency and its submodules).
# We just copy the assembled release into a slim runtime image.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 libncurses6 libsnappy1v5 liblz4-1 libzstd1 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY _build/prod/rel/beamchain /opt/beamchain

VOLUME /data
EXPOSE 48348 48338

ENTRYPOINT ["/opt/beamchain/bin/beamchain"]
CMD ["daemon"]
