# SATG tool sandbox. One disposable container per ALLOWED tool call.
# The gateway (backend/app/sandbox/docker_runner.py) runs it with:
#   --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges
#   --memory 256m --cpus 0.5 --pids-limit 64 --user 65532:65532, no mounts.
# Build: docker build -t satg-sandbox:0.1 sandbox/

# Pinned by digest so the image is reproducible.
FROM python:3.13-slim@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b

RUN groupadd --gid 65532 sandbox \
 && useradd --uid 65532 --gid 65532 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sandbox

# Code and fixtures are root-owned and read-only for the sandbox user.
COPY --chown=root:root runner.py /opt/satg/runner.py
COPY --chown=root:root tools/ /opt/satg/tools/
COPY --chown=root:root data/ /opt/satg/data/
RUN chmod -R a-w,a+rX /opt/satg

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /opt/satg
USER 65532:65532

# Fixed entrypoint: the runner only dispatches registered tools. -I isolates
# from environment variables and user site-packages; -B writes no .pyc.
ENTRYPOINT ["python", "-I", "-B", "/opt/satg/runner.py"]
