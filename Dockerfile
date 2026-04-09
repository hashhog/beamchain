# ---------- build ----------
FROM erlang:27-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        git gcc g++ make cmake automake autoconf libtool \
        libssl-dev libsnappy-dev liblz4-dev libzstd-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN rebar3 as prod release

# ---------- runtime ----------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 libncurses6 libsnappy1v5 liblz4-1 libzstd1 libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/_build/prod/rel/beamchain /opt/beamchain

VOLUME /data
EXPOSE 48348 48338

ENTRYPOINT ["/opt/beamchain/bin/beamchain"]
CMD ["daemon"]
