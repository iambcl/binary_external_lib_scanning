# BinSentry

## Run with Docker Compose

Start Docker Desktop, then build and start the container from this directory:

```sh
docker compose up -d --build
```

The image installs a `binsentry` console command. Show help or scan a binary:

```sh
docker compose exec binsentry binsentry --help
docker compose exec binsentry binsentry scan testdata/hello-linux-x86_64
```

To use the command directly in a container shell:

```sh
docker compose exec binsentry sh
binsentry --help
binsentry scan testdata/hello-linux-x86_64
```

For a temporary container without starting the service first:

```sh
docker compose run --rm --entrypoint binsentry binsentry scan testdata/hello-linux-x86_64
```

Compose builds the existing Dockerfile for `linux/amd64` and mounts the project
read-only at `/app`. The editable installation uses the mounted source, so edits
are available on the next run. Rebuild after changing `requirements.txt`,
`pyproject.toml`, or the Dockerfile. The container stays running using
`sleep infinity` until stopped with `docker compose down`.

The x86-64 platform matches the included Linux sample; Docker Desktop uses
emulation on Apple Silicon. Library resolution uses libraries installed inside
the container. Choose a matching platform for binaries of another architecture.

## Install locally

To register `binsentry` in a local Python environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
binsentry --help
```

Scanning currently uses Linux tools (`ldconfig`, `dpkg`, and `dpkg-query`), so use
the Docker container for scans on macOS.
