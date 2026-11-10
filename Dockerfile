# Trickle: Python server + Vector + LuaJIT in one small image.
# Build:  docker compose up -d --build        (see docker-compose.yml)

# Vector binary comes from the official image, so no download or install step here.
# To use a different Vector version:  docker compose build --build-arg VECTOR_VERSION=0.61.0
ARG VECTOR_VERSION=0.61.0
FROM timberio/vector:${VECTOR_VERSION}-debian AS vector

FROM python:3.12-slim AS base
RUN apt-get update \
 && apt-get install -y --no-install-recommends luajit ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=vector /usr/bin/vector /usr/local/bin/vector

RUN useradd --create-home --uid 10001 lab
WORKDIR /app
COPY server.py formats.py mockapi.py index.html lua_runner.lua collector_runner.lua ./
COPY pipelines ./pipelines
RUN mkdir -p /app/output /data && chown -R lab:lab /app /data

# Stage that compiles Busted (needs a compiler; the compiler does NOT ship in the final image).
FROM base AS rocks
USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends luarocks build-essential libluajit-5.1-dev \
 && rm -rf /var/lib/apt/lists/* \
 && luarocks --lua-version 5.1 --lua-dir /usr --tree /usr/local install busted LUA_INCDIR=/usr/include/luajit-2.1

# Test image:  docker compose --profile test run --rm tests
FROM rocks AS test
USER lab
ENV LUA_PATH="/usr/local/share/lua/5.1/?.lua;/usr/local/share/lua/5.1/?/init.lua;;" LUA_CPATH="/usr/local/lib/lua/5.1/?.so;;"
CMD ["/usr/local/bin/busted", "spec"]

# Runtime image (default; must stay the last stage)
FROM base AS app
# Busted (built in the rocks stage) powers the Run Busted button; LuaRocks itself is small.
RUN apt-get update && apt-get install -y --no-install-recommends luarocks && rm -rf /var/lib/apt/lists/*
COPY --from=rocks /usr/local/share/lua /usr/local/share/lua
COPY --from=rocks /usr/local/lib/lua /usr/local/lib/lua
COPY --from=rocks /usr/local/lib/luarocks /usr/local/lib/luarocks
COPY --from=rocks /usr/local/bin/busted /usr/local/bin/busted
COPY spec_live ./spec_live
RUN chown -R lab:lab /app
USER lab
ENV LUA_PATH="/usr/local/share/lua/5.1/?.lua;/usr/local/share/lua/5.1/?/init.lua;;" LUA_CPATH="/usr/local/lib/lua/5.1/?.so;;"

ENV HOST=0.0.0.0 PORT=8790 IN_DOCKER=1 PYTHONUNBUFFERED=1
EXPOSE 8790
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD python3 -c "import urllib.request,os; urllib.request.urlopen('http://127.0.0.1:%s/api/status' % os.environ.get('PORT','8790'), timeout=4)" || exit 1
CMD ["python3", "server.py"]
