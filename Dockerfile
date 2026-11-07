FROM php:8.5.12-cli

RUN apt-get update \
    && apt-get install -y --no-install-recommends git unzip libpq-dev \
    && docker-php-ext-install -j"$(nproc)" pdo_pgsql pcntl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2.10.3 /usr/bin/composer /usr/local/bin/composer

# The Composer wrapper downloads an unpinned latest binary on first use.
# Install the reviewed native release during explicit runtime setup instead.
RUN curl -fsSL https://github.com/denzyldick/phanalist/releases/download/v1.2.1/phanalist-x86_64-unknown-linux-gnu.tar.gz -o /tmp/phanalist.tar.gz \
    && echo "debbf9f9ee871b421e6d4fe66d16a9e5d8039ebbf3d48005a6199933380acb6a  /tmp/phanalist.tar.gz" | sha256sum -c - \
    && mkdir /tmp/phanalist \
    && tar -xzf /tmp/phanalist.tar.gz -C /tmp/phanalist \
    && find /tmp/phanalist -type f -name phanalist -exec install -m 0755 {} /usr/local/bin/phanalist \; \
    && /usr/local/bin/phanalist --version \
    && rm -rf /tmp/phanalist /tmp/phanalist.tar.gz

WORKDIR /app
