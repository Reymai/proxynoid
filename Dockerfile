# syntax=docker/dockerfile:1.7

ARG RUBY_VERSION=3.3
FROM ruby:${RUBY_VERSION}-alpine AS build

WORKDIR /app

RUN apk add --no-cache build-base git

COPY Gemfile Gemfile.lock* ./
RUN bundle config set --local without 'development test' \
 && bundle config set --local deployment 'true' \
 && bundle install --jobs=4 --retry=3

COPY . .

FROM ruby:${RUBY_VERSION}-alpine AS runtime

ENV RACK_ENV=production \
    BUNDLE_PATH=vendor/bundle \
    BUNDLE_WITHOUT=development:test \
    PORT=9292

RUN apk add --no-cache tini \
 && addgroup -S proxynoid \
 && adduser -S -G proxynoid -u 1000 proxynoid \
 && mkdir -p /app \
 && chown proxynoid:proxynoid /app

WORKDIR /app
USER proxynoid

COPY --from=build --chown=proxynoid:proxynoid /app /app

EXPOSE 9292

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q -O - http://127.0.0.1:9292/healthz || exit 1

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["bundle", "exec", "ruby", "bin/server"]
